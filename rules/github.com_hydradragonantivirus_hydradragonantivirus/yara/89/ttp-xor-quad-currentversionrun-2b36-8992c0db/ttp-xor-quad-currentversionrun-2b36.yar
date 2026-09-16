rule TTP_XOR_QUAD_CurrentVersionRun_2b36 {
  strings:
    $key_2b36 = { 78 59 [2] 5c 57 [2] 77 7b [2] 59 59 [2] 4d 42 [2] 42 58 [2] 5c 45 [2] 5e 44 [2] 45 42 [2] 59 45 [2] 45 6a }

  condition:
    any of them
}