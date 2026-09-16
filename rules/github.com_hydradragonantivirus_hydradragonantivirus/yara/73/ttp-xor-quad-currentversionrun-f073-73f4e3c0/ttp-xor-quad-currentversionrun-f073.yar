rule TTP_XOR_QUAD_CurrentVersionRun_f073 {
  strings:
    $key_f073 = { a3 1c [2] 87 12 [2] ac 3e [2] 82 1c [2] 96 07 [2] 99 1d [2] 87 00 [2] 85 01 [2] 9e 07 [2] 82 00 [2] 9e 2f }

  condition:
    any of them
}