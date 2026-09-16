rule INFO_PE_Contains_404_Title
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-16"
        version = "1.0"
        description = "track executable files with equities related to a 404 response page"
        DaysofYARA = "16/100"

    strings:
        $ = "<title>404" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}