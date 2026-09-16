rule SUSP_Macho_Execution_BinZsh
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like zsh shell"

    strings:
        $ = "bin/zsh" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and all of them
}