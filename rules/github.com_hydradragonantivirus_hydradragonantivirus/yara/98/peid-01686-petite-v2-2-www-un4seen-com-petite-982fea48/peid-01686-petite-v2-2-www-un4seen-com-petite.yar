import "pe"
rule PEiD_01686_Petite_v2_2____www_un4seen_com_petite_
{
    meta:
        description = "[Petite v2.2 -> www.un4seen.com/petite]"
        ep_only = "true"
    strings:
        $a = {B8 00 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00}
    condition:
        $a at pe.entry_point
}