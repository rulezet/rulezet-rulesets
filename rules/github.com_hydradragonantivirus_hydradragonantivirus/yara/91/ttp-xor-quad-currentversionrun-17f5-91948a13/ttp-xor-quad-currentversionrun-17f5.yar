rule TTP_XOR_QUAD_CurrentVersionRun_17f5 {
  strings:
    $key_17f5 = { 44 9a [2] 60 94 [2] 4b b8 [2] 65 9a [2] 71 81 [2] 7e 9b [2] 60 86 [2] 62 87 [2] 79 81 [2] 65 86 [2] 79 a9 }

  condition:
    any of them
}