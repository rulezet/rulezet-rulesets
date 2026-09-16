rule TTP_XOR_QUAD_CurrentVersionRun_1df4 {
  strings:
    $key_1df4 = { 4e 9b [2] 6a 95 [2] 41 b9 [2] 6f 9b [2] 7b 80 [2] 74 9a [2] 6a 87 [2] 68 86 [2] 73 80 [2] 6f 87 [2] 73 a8 }

  condition:
    any of them
}