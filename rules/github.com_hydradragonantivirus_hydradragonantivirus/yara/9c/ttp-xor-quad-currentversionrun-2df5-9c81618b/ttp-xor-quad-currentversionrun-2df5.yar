rule TTP_XOR_QUAD_CurrentVersionRun_2df5 {
  strings:
    $key_2df5 = { 7e 9a [2] 5a 94 [2] 71 b8 [2] 5f 9a [2] 4b 81 [2] 44 9b [2] 5a 86 [2] 58 87 [2] 43 81 [2] 5f 86 [2] 43 a9 }

  condition:
    any of them
}