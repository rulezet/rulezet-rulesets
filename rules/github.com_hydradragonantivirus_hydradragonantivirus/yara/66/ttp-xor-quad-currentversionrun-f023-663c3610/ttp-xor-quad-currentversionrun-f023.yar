rule TTP_XOR_QUAD_CurrentVersionRun_f023 {
  strings:
    $key_f023 = { a3 4c [2] 87 42 [2] ac 6e [2] 82 4c [2] 96 57 [2] 99 4d [2] 87 50 [2] 85 51 [2] 9e 57 [2] 82 50 [2] 9e 7f }

  condition:
    any of them
}