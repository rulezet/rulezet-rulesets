rule TTP_XOR_QUAD_CurrentVersionRun_49fa {
  strings:
    $key_49fa = { 1a 95 [2] 3e 9b [2] 15 b7 [2] 3b 95 [2] 2f 8e [2] 20 94 [2] 3e 89 [2] 3c 88 [2] 27 8e [2] 3b 89 [2] 27 a6 }

  condition:
    any of them
}