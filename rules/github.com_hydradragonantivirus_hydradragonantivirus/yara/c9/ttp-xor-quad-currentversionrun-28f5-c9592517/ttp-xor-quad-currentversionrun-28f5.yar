rule TTP_XOR_QUAD_CurrentVersionRun_28f5 {
  strings:
    $key_28f5 = { 7b 9a [2] 5f 94 [2] 74 b8 [2] 5a 9a [2] 4e 81 [2] 41 9b [2] 5f 86 [2] 5d 87 [2] 46 81 [2] 5a 86 [2] 46 a9 }

  condition:
    any of them
}