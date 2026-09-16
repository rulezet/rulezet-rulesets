rule TTP_XOR_QUAD_CurrentVersionRun_4916 {
  strings:
    $key_4916 = { 1a 79 [2] 3e 77 [2] 15 5b [2] 3b 79 [2] 2f 62 [2] 20 78 [2] 3e 65 [2] 3c 64 [2] 27 62 [2] 3b 65 [2] 27 4a }

  condition:
    any of them
}