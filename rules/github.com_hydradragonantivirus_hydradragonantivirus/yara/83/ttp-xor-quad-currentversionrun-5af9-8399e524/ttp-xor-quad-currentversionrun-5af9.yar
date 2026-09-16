rule TTP_XOR_QUAD_CurrentVersionRun_5af9 {
  strings:
    $key_5af9 = { 09 96 [2] 2d 98 [2] 06 b4 [2] 28 96 [2] 3c 8d [2] 33 97 [2] 2d 8a [2] 2f 8b [2] 34 8d [2] 28 8a [2] 34 a5 }

  condition:
    any of them
}