rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48de784388fe1cb207743db33bf6880e1c19a91f659ce30d4ae640917e21d31a"

  strings:
    $s1  = "    Expand and execute COMMANDS as long as the final command in the" fullword ascii
    $s2  = "compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix" ascii
    $s3  = "compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix" ascii
    $s4  = "complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpa" ascii
    $s5  = "    Getopts normally parses the positional parameters ($0 - $9), but if" fullword ascii
    $s6  = "    Unless forced, login shells cannot be suspended." fullword ascii
    $s7  = "    If the -n option is supplied, waits for the next job to terminate and" fullword ascii
    $s8  = "@(#)Bash version 4.4.12(3) release GNU" fullword ascii
    $s9  = "    `while' COMMANDS has an exit status of zero." fullword ascii
    $s10 = "    HOME shell variable." fullword ascii
    $s11 = "    `until' COMMANDS has an exit status which is not zero." fullword ascii
    $s12 = "brace expansion: failed to allocate memory for %d elements" fullword ascii
    $s13 = "    status is zero.  If ID is a a job specification, waits for all processes" fullword ascii
    $s14 = "] [-S suffix] [word]" fullword ascii
    $s15 = "ulimit [-SHabcdefiklmnpqrstuvxPT] [limit]" fullword ascii
    $s16 = "delete the history entry at position OFFSET." fullword ascii
    $s17 = "    precedence over -E." fullword ascii
    $s18 = "    arguments, list all shell options with an indication of whether or not each" fullword ascii
    $s19 = "    not a shell builtin.." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}