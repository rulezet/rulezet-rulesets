rule TTP_XOR_QUAD_CurrentVersionRun_1df8 {
  strings:
    $key_1df8 = { 4e 97 [2] 6a 99 [2] 41 b5 [2] 6f 97 [2] 7b 8c [2] 74 96 [2] 6a 8b [2] 68 8a [2] 73 8c [2] 6f 8b [2] 73 a4 }

  condition:
    any of them
}