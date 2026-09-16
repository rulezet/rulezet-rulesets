rule TTP_XOR_QUAD_CurrentVersionRun_4bf5 {
  strings:
    $key_4bf5 = { 18 9a [2] 3c 94 [2] 17 b8 [2] 39 9a [2] 2d 81 [2] 22 9b [2] 3c 86 [2] 3e 87 [2] 25 81 [2] 39 86 [2] 25 a9 }

  condition:
    any of them
}