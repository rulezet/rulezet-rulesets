rule TTP_XOR_QUAD_CurrentVersionRun_7378 {
  strings:
    $key_7378 = { 20 17 [2] 04 19 [2] 2f 35 [2] 01 17 [2] 15 0c [2] 1a 16 [2] 04 0b [2] 06 0a [2] 1d 0c [2] 01 0b [2] 1d 24 }

  condition:
    any of them
}