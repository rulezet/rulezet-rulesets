rule TTP_XOR_QUAD_CurrentVersionRun_7bfa {
  strings:
    $key_7bfa = { 28 95 [2] 0c 9b [2] 27 b7 [2] 09 95 [2] 1d 8e [2] 12 94 [2] 0c 89 [2] 0e 88 [2] 15 8e [2] 09 89 [2] 15 a6 }

  condition:
    any of them
}