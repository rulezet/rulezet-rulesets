rule PEiD_01061_Microsoft_Visual_C__v7_0___Basic__NET_
{
    meta:
        description = "[Microsoft Visual C# v7.0 / Basic .NET]"
        ep_only = "false"
    strings:
        $a = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}