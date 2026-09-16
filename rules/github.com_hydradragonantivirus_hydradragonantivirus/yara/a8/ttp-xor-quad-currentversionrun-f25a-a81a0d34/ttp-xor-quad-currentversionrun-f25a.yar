rule TTP_XOR_QUAD_CurrentVersionRun_f25a {
  strings:
    $key_f25a = { a1 35 [2] 85 3b [2] ae 17 [2] 80 35 [2] 94 2e [2] 9b 34 [2] 85 29 [2] 87 28 [2] 9c 2e [2] 80 29 [2] 9c 06 }

  condition:
    any of them
}