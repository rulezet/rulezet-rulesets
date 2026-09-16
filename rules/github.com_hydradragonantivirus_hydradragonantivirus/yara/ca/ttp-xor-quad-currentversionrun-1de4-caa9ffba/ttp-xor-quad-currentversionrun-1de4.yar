rule TTP_XOR_QUAD_CurrentVersionRun_1de4 {
  strings:
    $key_1de4 = { 4e 8b [2] 6a 85 [2] 41 a9 [2] 6f 8b [2] 7b 90 [2] 74 8a [2] 6a 97 [2] 68 96 [2] 73 90 [2] 6f 97 [2] 73 b8 }

  condition:
    any of them
}