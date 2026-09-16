rule TTP_XOR_QUAD_CurrentVersionRun_7b54 {
  strings:
    $key_7b54 = { 28 3b [2] 0c 35 [2] 27 19 [2] 09 3b [2] 1d 20 [2] 12 3a [2] 0c 27 [2] 0e 26 [2] 15 20 [2] 09 27 [2] 15 08 }

  condition:
    any of them
}