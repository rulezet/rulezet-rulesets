rule TTP_XOR_QUAD_CurrentVersionRun_f25d {
  strings:
    $key_f25d = { a1 32 [2] 85 3c [2] ae 10 [2] 80 32 [2] 94 29 [2] 9b 33 [2] 85 2e [2] 87 2f [2] 9c 29 [2] 80 2e [2] 9c 01 }

  condition:
    any of them
}