rule TTP_XOR_QUAD_CurrentVersionRun_5ae8 {
  strings:
    $key_5ae8 = { 09 87 [2] 2d 89 [2] 06 a5 [2] 28 87 [2] 3c 9c [2] 33 86 [2] 2d 9b [2] 2f 9a [2] 34 9c [2] 28 9b [2] 34 b4 }

  condition:
    any of them
}