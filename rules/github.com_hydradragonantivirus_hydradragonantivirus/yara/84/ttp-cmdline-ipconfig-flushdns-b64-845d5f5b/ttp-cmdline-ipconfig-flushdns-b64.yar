rule ttp_cmdline_ipconfig_flushdns_b64 {
  meta:
    author = "stvemillertime"
    desc   = "Looks for suspicious cmdline string in a PE"
    ref    = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"

  strings:
    $a  = "flushdns" base64 base64wide
    $z2 = { 69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00 }      $z3 = { 4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00 }      $z4 = "FlushDnsPolicyUnreachableStatus"
    $z5 = "flushdns</userInput>"

  condition:
    uint16be(0) == 0x4d5a
    and $a
    and not any of ($z*)
}