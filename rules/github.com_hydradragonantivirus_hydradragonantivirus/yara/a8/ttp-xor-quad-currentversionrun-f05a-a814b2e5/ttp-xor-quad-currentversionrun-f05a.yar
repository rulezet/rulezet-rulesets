rule TTP_XOR_QUAD_CurrentVersionRun_f05a {
  strings:
    $key_f05a = { a3 35 [2] 87 3b [2] ac 17 [2] 82 35 [2] 96 2e [2] 99 34 [2] 87 29 [2] 85 28 [2] 9e 2e [2] 82 29 [2] 9e 06 }

  condition:
    any of them
}