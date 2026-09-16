rule TTP_XOR_QUAD_CurrentVersionRun_39f5 {
  strings:
    $key_39f5 = { 6a 9a [2] 4e 94 [2] 65 b8 [2] 4b 9a [2] 5f 81 [2] 50 9b [2] 4e 86 [2] 4c 87 [2] 57 81 [2] 4b 86 [2] 57 a9 }

  condition:
    any of them
}