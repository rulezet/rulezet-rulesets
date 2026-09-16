rule PEiD_01400_Obsidium_v1_0_0_61_
{
    meta:
        description = "[Obsidium v1.0.0.61]"
        ep_only = "true"
    strings:
        $a = {E8 AF 1C 00 00}
    condition:
        $a
}