import "pe"
rule PEiD_01101_Microsoft_Visual_C___v5_0_v6_0__MFC__
{
    meta:
        description = "[Microsoft Visual C++ v5.0/v6.0 (MFC)]"
        ep_only = "true"
    strings:
        $a = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50}
    condition:
        $a at pe.entry_point
}