rule TTP_XOR_QUAD_CurrentVersionRun_1dfa {
  strings:
    $key_1dfa = { 4e 95 [2] 6a 9b [2] 41 b7 [2] 6f 95 [2] 7b 8e [2] 74 94 [2] 6a 89 [2] 68 88 [2] 73 8e [2] 6f 89 [2] 73 a6 }

  condition:
    any of them
}