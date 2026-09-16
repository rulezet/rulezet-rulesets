rule TTP_XOR_QUAD_CurrentVersionRun_f013 {
  strings:
    $key_f013 = { a3 7c [2] 87 72 [2] ac 5e [2] 82 7c [2] 96 67 [2] 99 7d [2] 87 60 [2] 85 61 [2] 9e 67 [2] 82 60 [2] 9e 4f }

  condition:
    any of them
}