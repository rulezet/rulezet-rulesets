rule TTP_XOR_QUAD_CurrentVersionRun_0dfa {
  strings:
    $key_0dfa = { 5e 95 [2] 7a 9b [2] 51 b7 [2] 7f 95 [2] 6b 8e [2] 64 94 [2] 7a 89 [2] 78 88 [2] 63 8e [2] 7f 89 [2] 63 a6 }

  condition:
    any of them
}