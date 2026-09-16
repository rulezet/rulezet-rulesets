rule TTP_XOR_QUAD_CurrentVersionRun_7cfa {
  strings:
    $key_7cfa = { 2f 95 [2] 0b 9b [2] 20 b7 [2] 0e 95 [2] 1a 8e [2] 15 94 [2] 0b 89 [2] 09 88 [2] 12 8e [2] 0e 89 [2] 12 a6 }

  condition:
    any of them
}