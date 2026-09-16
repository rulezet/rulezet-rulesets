rule TTP_XOR_QUAD_CurrentVersionRun_7dfa {
  strings:
    $key_7dfa = { 2e 95 [2] 0a 9b [2] 21 b7 [2] 0f 95 [2] 1b 8e [2] 14 94 [2] 0a 89 [2] 08 88 [2] 13 8e [2] 0f 89 [2] 13 a6 }

  condition:
    any of them
}