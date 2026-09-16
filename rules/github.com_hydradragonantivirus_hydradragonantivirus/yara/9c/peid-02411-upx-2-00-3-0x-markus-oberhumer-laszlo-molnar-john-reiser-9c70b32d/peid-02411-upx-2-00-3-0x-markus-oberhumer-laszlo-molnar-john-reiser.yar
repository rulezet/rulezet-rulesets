rule PEiD_02411_UPX_2_00_3_0X____Markus_Oberhumer___Laszlo_Molnar___John_Reiser_
{
    meta:
        description = "[UPX 2.00-3.0X -> Markus Oberhumer & Laszlo Molnar & John Reiser]"
        ep_only = "false"
    strings:
        $a = {5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF}
    condition:
        $a
}