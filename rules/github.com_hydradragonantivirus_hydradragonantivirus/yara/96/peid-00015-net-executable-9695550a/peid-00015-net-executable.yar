rule PEiD_00015__NET_executable_
{
    meta:
        description = "[.NET executable]"
        ep_only = "true"
    strings:
        $a = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}