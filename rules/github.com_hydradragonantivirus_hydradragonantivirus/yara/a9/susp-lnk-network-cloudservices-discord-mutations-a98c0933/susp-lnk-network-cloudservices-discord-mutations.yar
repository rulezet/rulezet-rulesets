rule SUSP_LNK_Network_CloudServices_Discord_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $discord_base64              = "discord" base64 base64wide
    $discord_xor                 = "discord" xor(0x01-0xff) ascii wide
    $discord_flipflop            = "idcsrod" nocase ascii wide
    $discord_reverse             = "drocsid" nocase ascii wide
    $discord_hex_enc_str         = "646973636f7264" nocase ascii wide
    $discord_decimal             = "100 105 115 99 111 114 100" nocase ascii wide
    $discord_fallchill           = "wrhxliw" nocase ascii wide
    $discord_stackpush           = "hordhdisc" nocase ascii wide
    $discord_stackpushnull       = "hord\x00hdisc"
    $discord_stackpushdoublenull = "hord\x00\x00hdisc"

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}