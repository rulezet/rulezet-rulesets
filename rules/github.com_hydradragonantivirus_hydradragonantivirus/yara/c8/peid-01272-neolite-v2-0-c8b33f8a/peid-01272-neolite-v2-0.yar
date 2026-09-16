import "pe"
rule PEiD_01272_Neolite_v2_0_
{
    meta:
        description = "[Neolite v2.0]"
        ep_only = "true"
    strings:
        $a = {E9 A6 00 00 00}
    condition:
        $a at pe.entry_point
}