import "pe"
rule PEiD_01127_Microsoft_Visual_C___
{
    meta:
        description = "[Microsoft Visual C++]"
        ep_only = "true"
    strings:
        $a = {8B 44 24 08 83 ?? ?? 74}
    condition:
        $a at pe.entry_point
}