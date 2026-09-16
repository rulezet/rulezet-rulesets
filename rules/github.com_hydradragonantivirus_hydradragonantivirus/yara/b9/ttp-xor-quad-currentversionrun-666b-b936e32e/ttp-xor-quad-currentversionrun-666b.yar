rule TTP_XOR_QUAD_CurrentVersionRun_666b {
  strings:
    $key_666b = { 35 04 [2] 11 0a [2] 3a 26 [2] 14 04 [2] 00 1f [2] 0f 05 [2] 11 18 [2] 13 19 [2] 08 1f [2] 14 18 [2] 08 37 }

  condition:
    any of them
}