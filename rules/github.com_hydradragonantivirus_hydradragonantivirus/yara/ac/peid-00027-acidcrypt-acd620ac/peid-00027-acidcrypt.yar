rule PEiD_00027_AcidCrypt_
{
    meta:
        description = "[AcidCrypt]"
        ep_only = "true"
    strings:
        $a = {BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB}
    condition:
        $a
}