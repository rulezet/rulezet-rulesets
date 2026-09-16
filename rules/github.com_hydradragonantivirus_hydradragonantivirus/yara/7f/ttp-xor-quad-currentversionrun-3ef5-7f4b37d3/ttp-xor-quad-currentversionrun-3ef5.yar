rule TTP_XOR_QUAD_CurrentVersionRun_3ef5 {
  strings:
    $key_3ef5 = { 6d 9a [2] 49 94 [2] 62 b8 [2] 4c 9a [2] 58 81 [2] 57 9b [2] 49 86 [2] 4b 87 [2] 50 81 [2] 4c 86 [2] 50 a9 }

  condition:
    any of them
}