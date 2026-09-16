rule PEiD_01129_Microsoft_WAV_Audio_file_
{
    meta:
        description = "[Microsoft WAV Audio file]"
        ep_only = "false"
    strings:
        $a = {52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74}
    condition:
        $a
}