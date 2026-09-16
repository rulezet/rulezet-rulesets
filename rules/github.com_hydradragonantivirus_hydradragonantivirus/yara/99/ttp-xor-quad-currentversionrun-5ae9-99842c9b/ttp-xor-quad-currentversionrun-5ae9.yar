rule TTP_XOR_QUAD_CurrentVersionRun_5ae9 {
  strings:
    $key_5ae9 = { 09 86 [2] 2d 88 [2] 06 a4 [2] 28 86 [2] 3c 9d [2] 33 87 [2] 2d 9a [2] 2f 9b [2] 34 9d [2] 28 9a [2] 34 b5 }

  condition:
    any of them
}