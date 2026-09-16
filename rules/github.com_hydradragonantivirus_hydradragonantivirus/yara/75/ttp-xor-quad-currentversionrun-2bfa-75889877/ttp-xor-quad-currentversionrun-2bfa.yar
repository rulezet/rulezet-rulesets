rule TTP_XOR_QUAD_CurrentVersionRun_2bfa {
  strings:
    $key_2bfa = { 78 95 [2] 5c 9b [2] 77 b7 [2] 59 95 [2] 4d 8e [2] 42 94 [2] 5c 89 [2] 5e 88 [2] 45 8e [2] 59 89 [2] 45 a6 }

  condition:
    any of them
}