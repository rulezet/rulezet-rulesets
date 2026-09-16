rule TTP_XOR_QUAD_CurrentVersionRun_5af4 {
  strings:
    $key_5af4 = { 09 9b [2] 2d 95 [2] 06 b9 [2] 28 9b [2] 3c 80 [2] 33 9a [2] 2d 87 [2] 2f 86 [2] 34 80 [2] 28 87 [2] 34 a8 }

  condition:
    any of them
}