rule PEiD_01128_Microsoft_Visual_Studio__NET_
{
    meta:
        description = "[Microsoft Visual Studio .NET]"
        ep_only = "true"
    strings:
        $a = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}