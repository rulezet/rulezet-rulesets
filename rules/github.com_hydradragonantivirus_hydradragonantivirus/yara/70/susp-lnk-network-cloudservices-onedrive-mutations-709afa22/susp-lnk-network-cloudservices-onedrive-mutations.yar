rule SUSP_LNK_Network_CloudServices_OneDrive_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $onedrive_base64              = "onedrive" base64 base64wide
    $onedrive_xor                 = "onedrive" xor(0x01-0xff) ascii wide
    $onedrive_flipflop            = "nodeirev" nocase ascii wide
    $onedrive_reverse             = "evirdeno" nocase ascii wide
    $onedrive_hex_enc_str         = "6f6e656472697665" nocase ascii wide
    $onedrive_decimal             = "111 110 101 100 114 105 118 101" nocase ascii wide
    $onedrive_fallchill           = "lmvwirev" nocase ascii wide
    $onedrive_stackpush           = "hrivehoned" nocase ascii wide
    $onedrive_stackpushnull       = "hrive\x00honed"
    $onedrive_stackpushdoublenull = "hrive\x00\x00honed"

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}