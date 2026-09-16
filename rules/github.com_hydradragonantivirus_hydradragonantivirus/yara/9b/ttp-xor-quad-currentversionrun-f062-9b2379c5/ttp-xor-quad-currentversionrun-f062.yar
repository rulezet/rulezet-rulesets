rule TTP_XOR_QUAD_CurrentVersionRun_f062 {
  strings:
    $key_f062 = { a3 0d [2] 87 03 [2] ac 2f [2] 82 0d [2] 96 16 [2] 99 0c [2] 87 11 [2] 85 10 [2] 9e 16 [2] 82 11 [2] 9e 3e }

  condition:
    any of them
}