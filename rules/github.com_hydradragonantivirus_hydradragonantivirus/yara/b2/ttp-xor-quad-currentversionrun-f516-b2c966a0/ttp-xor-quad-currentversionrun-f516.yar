rule TTP_XOR_QUAD_CurrentVersionRun_f516 {
  strings:
    $key_f516 = { a6 79 [2] 82 77 [2] a9 5b [2] 87 79 [2] 93 62 [2] 9c 78 [2] 82 65 [2] 80 64 [2] 9b 62 [2] 87 65 [2] 9b 4a }

  condition:
    any of them
}