rule TTP_XOR_QUAD_CurrentVersionRun_1df9 {
  strings:
    $key_1df9 = { 4e 96 [2] 6a 98 [2] 41 b4 [2] 6f 96 [2] 7b 8d [2] 74 97 [2] 6a 8a [2] 68 8b [2] 73 8d [2] 6f 8a [2] 73 a5 }

  condition:
    any of them
}