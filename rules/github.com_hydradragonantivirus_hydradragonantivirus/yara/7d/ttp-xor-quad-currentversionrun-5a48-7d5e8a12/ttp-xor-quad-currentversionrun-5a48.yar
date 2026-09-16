rule TTP_XOR_QUAD_CurrentVersionRun_5a48 {
  strings:
    $key_5a48 = { 09 27 [2] 2d 29 [2] 06 05 [2] 28 27 [2] 3c 3c [2] 33 26 [2] 2d 3b [2] 2f 3a [2] 34 3c [2] 28 3b [2] 34 14 }

  condition:
    any of them
}