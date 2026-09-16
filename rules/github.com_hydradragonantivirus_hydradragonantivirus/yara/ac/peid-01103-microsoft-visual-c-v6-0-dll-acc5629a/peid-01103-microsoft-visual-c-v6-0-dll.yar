rule PEiD_01103_Microsoft_Visual_C___v6_0_DLL_
{
    meta:
        description = "[Microsoft Visual C++ v6.0 DLL]"
        ep_only = "true"
    strings:
        $a = {55 8B EC 53 8B 5D 08 56 8B 75 0C}
    condition:
        $a
}