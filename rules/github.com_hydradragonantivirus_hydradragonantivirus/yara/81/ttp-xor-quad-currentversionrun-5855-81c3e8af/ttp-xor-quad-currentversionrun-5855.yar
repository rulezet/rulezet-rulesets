rule TTP_XOR_QUAD_CurrentVersionRun_5855 {
  strings:
    $key_5855 = { 0b 3a [2] 2f 34 [2] 04 18 [2] 2a 3a [2] 3e 21 [2] 31 3b [2] 2f 26 [2] 2d 27 [2] 36 21 [2] 2a 26 [2] 36 09 }

  condition:
    any of them
}