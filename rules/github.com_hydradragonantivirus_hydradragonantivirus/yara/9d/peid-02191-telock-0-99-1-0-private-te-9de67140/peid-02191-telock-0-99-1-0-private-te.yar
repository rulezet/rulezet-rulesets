rule PEiD_02191_tElock_0_99___1_0_private____tE__
{
    meta:
        description = "[tElock 0.99 - 1.0 private -> tE!]"
        ep_only = "true"
    strings:
        $a = {E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}