rule INFO_PE_HttpSendResponseEntityBody_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpSendResponseEntityBody, which will be used to respond to inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpSendResponseEntityBody" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}