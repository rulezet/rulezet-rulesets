rule TTP_XOR_QUAD_CurrentVersionRun_1b36 {
  strings:
    $key_1b36 = { 48 59 [2] 6c 57 [2] 47 7b [2] 69 59 [2] 7d 42 [2] 72 58 [2] 6c 45 [2] 6e 44 [2] 75 42 [2] 69 45 [2] 75 6a }

  condition:
    any of them
}