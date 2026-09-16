rule TTP_XOR_QUAD_CurrentVersionRun_5a18 {
  strings:
    $key_5a18 = { 09 77 [2] 2d 79 [2] 06 55 [2] 28 77 [2] 3c 6c [2] 33 76 [2] 2d 6b [2] 2f 6a [2] 34 6c [2] 28 6b [2] 34 44 }

  condition:
    any of them
}