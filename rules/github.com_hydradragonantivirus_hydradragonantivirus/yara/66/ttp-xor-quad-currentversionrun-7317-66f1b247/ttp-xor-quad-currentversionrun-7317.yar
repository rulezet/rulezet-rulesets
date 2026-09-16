rule TTP_XOR_QUAD_CurrentVersionRun_7317 {
  strings:
    $key_7317 = { 20 78 [2] 04 76 [2] 2f 5a [2] 01 78 [2] 15 63 [2] 1a 79 [2] 04 64 [2] 06 65 [2] 1d 63 [2] 01 64 [2] 1d 4b }

  condition:
    any of them
}