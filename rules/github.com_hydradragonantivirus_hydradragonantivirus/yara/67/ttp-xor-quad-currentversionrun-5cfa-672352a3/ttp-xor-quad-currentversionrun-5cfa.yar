rule TTP_XOR_QUAD_CurrentVersionRun_5cfa {
  strings:
    $key_5cfa = { 0f 95 [2] 2b 9b [2] 00 b7 [2] 2e 95 [2] 3a 8e [2] 35 94 [2] 2b 89 [2] 29 88 [2] 32 8e [2] 2e 89 [2] 32 a6 }

  condition:
    any of them
}