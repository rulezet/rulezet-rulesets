rule NTLM_Credential_Theft_via_PDF
{
    strings:
                $badness1 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)/ nocase
        $badness2 = /\s*\/AA\s*<<\s*\/[OC]\s*<<\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))/ nocase
        $badness3 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])\s*\/F\s*\(\\\\\\\\[a-z0-9]+.[^\\]+\\\\[a-z0-9]+\)(\s*\/\D\s*\[[^\]]+\]))/ nocase

    condition:
        for any i in (0..1024) : (uint32be(i) == 0x25504446) and any of ($badness*)
}