rule TTP_XOR_QUAD_CurrentVersionRun_f316 {
  strings:
    $key_f316 = { a0 79 [2] 84 77 [2] af 5b [2] 81 79 [2] 95 62 [2] 9a 78 [2] 84 65 [2] 86 64 [2] 9d 62 [2] 81 65 [2] 9d 4a }

  condition:
    any of them
}