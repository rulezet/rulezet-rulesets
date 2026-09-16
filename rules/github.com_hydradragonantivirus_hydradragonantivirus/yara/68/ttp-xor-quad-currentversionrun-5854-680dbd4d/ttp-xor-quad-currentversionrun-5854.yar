rule TTP_XOR_QUAD_CurrentVersionRun_5854 {
  strings:
    $key_5854 = { 0b 3b [2] 2f 35 [2] 04 19 [2] 2a 3b [2] 3e 20 [2] 31 3a [2] 2f 27 [2] 2d 26 [2] 36 20 [2] 2a 27 [2] 36 08 }

  condition:
    any of them
}