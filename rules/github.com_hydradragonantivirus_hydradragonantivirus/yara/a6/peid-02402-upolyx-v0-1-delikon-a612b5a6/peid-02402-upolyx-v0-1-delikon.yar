rule PEiD_02402_UPolyX_V0_1____Delikon_
{
    meta:
        description = "[UPolyX V0.1 -> Delikon]"
        ep_only = "false"
    strings:
        $a = {E2 ?? FF ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}