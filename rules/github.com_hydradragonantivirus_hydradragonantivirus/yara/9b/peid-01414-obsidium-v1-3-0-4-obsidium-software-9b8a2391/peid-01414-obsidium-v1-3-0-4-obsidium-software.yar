rule PEiD_01414_Obsidium_V1_3_0_4____Obsidium_Software_
{
    meta:
        description = "[Obsidium V1.3.0.4 -> Obsidium Software]"
        ep_only = "true"
    strings:
        $a = {EB 02 ?? ?? E8 ?? 00 00 00}
    condition:
        $a
}