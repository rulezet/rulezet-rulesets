rule TTP_XOR_QUAD_CurrentVersionRun_f003 {
  strings:
    $key_f003 = { a3 6c [2] 87 62 [2] ac 4e [2] 82 6c [2] 96 77 [2] 99 6d [2] 87 70 [2] 85 71 [2] 9e 77 [2] 82 70 [2] 9e 5f }

  condition:
    any of them
}