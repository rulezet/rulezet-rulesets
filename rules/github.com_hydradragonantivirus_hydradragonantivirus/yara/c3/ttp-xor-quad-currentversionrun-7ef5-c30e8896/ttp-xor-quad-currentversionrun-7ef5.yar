rule TTP_XOR_QUAD_CurrentVersionRun_7ef5 {
  strings:
    $key_7ef5 = { 2d 9a [2] 09 94 [2] 22 b8 [2] 0c 9a [2] 18 81 [2] 17 9b [2] 09 86 [2] 0b 87 [2] 10 81 [2] 0c 86 [2] 10 a9 }

  condition:
    any of them
}