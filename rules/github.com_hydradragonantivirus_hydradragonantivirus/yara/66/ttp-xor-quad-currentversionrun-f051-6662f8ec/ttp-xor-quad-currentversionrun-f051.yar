rule TTP_XOR_QUAD_CurrentVersionRun_f051 {
  strings:
    $key_f051 = { a3 3e [2] 87 30 [2] ac 1c [2] 82 3e [2] 96 25 [2] 99 3f [2] 87 22 [2] 85 23 [2] 9e 25 [2] 82 22 [2] 9e 0d }

  condition:
    any of them
}