rule TTP_XOR_QUAD_CurrentVersionRun_5255 {
  strings:
    $key_5255 = { 01 3a [2] 25 34 [2] 0e 18 [2] 20 3a [2] 34 21 [2] 3b 3b [2] 25 26 [2] 27 27 [2] 3c 21 [2] 20 26 [2] 3c 09 }

  condition:
    any of them
}