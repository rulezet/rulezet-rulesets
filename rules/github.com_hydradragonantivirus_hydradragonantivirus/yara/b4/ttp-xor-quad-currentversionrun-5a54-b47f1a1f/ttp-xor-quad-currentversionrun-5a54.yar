rule TTP_XOR_QUAD_CurrentVersionRun_5a54 {
  strings:
    $key_5a54 = { 09 3b [2] 2d 35 [2] 06 19 [2] 28 3b [2] 3c 20 [2] 33 3a [2] 2d 27 [2] 2f 26 [2] 34 20 [2] 28 27 [2] 34 08 }

  condition:
    any of them
}