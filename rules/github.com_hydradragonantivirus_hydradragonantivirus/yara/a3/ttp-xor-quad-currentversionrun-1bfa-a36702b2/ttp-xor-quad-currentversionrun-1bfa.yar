rule TTP_XOR_QUAD_CurrentVersionRun_1bfa {
  strings:
    $key_1bfa = { 48 95 [2] 6c 9b [2] 47 b7 [2] 69 95 [2] 7d 8e [2] 72 94 [2] 6c 89 [2] 6e 88 [2] 75 8e [2] 69 89 [2] 75 a6 }

  condition:
    any of them
}