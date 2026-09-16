rule TTP_XOR_QUAD_CurrentVersionRun_2dfa {
  strings:
    $key_2dfa = { 7e 95 [2] 5a 9b [2] 71 b7 [2] 5f 95 [2] 4b 8e [2] 44 94 [2] 5a 89 [2] 58 88 [2] 43 8e [2] 5f 89 [2] 43 a6 }

  condition:
    any of them
}