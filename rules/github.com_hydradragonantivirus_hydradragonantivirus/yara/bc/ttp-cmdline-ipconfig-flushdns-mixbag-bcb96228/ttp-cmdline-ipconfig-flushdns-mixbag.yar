rule ttp_cmdline_ipconfig_flushdns_mixbag {
  meta:
    author = "stvemillertime"
    desc   = "Looks for suspicious cmdline string in a PE"
    ref    = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"

  strings:
    $flushdns_flipflop            = "lfsudhsn" nocase
    $flushdns_reverse             = "sndhsulf" nocase
    $flushdns_hex_enc_str         = "666c757368646e73" nocase
    $flushdns_decimal             = "102 108 117 115 104 100 110 115" nocase
    $flushdns_fallchill           = "uofhswmh" nocase
    $flushdns_stackpush           = "hhdnshflus" nocase
    $flushdns_stackpushnull       = "h\x00hdnshflus" nocase
    $flushdns_stackpushdoublenull = "h\x00\x00hdnshflus" nocase
    $flushdns_hex_movebp          = { c6 45 ?? 66 c6 45 ?? 6c c6 45 ?? 75 c6 45 ?? 73 c6 45 ?? 68 c6 45 ?? 64 c6 45 ?? 6e c6 45 ?? 73 }
    $flushdns_rot13               = "syhfuqaf" nocase
    $z2                           = { 69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00 }      $z3                           = { 4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00 }      $z4                           = "FlushDnsPolicyUnreachableStatus"
    $z5                           = "flushdns</userInput>"

  condition:
    uint16be(0) == 0x4d5a
    and any of ($flushdns*)
    and not any of ($z*)
}