rule TTP_XOR_QUAD_CurrentVersionRun_5af8 {
  strings:
    $key_5af8 = { 09 97 [2] 2d 99 [2] 06 b5 [2] 28 97 [2] 3c 8c [2] 33 96 [2] 2d 8b [2] 2f 8a [2] 34 8c [2] 28 8b [2] 34 a4 }

  condition:
    any of them
}