rule TTP_XOR_QUAD_CurrentVersionRun_f040 {
  strings:
    $key_f040 = { a3 2f [2] 87 21 [2] ac 0d [2] 82 2f [2] 96 34 [2] 99 2e [2] 87 33 [2] 85 32 [2] 9e 34 [2] 82 33 [2] 9e 1c }

  condition:
    any of them
}