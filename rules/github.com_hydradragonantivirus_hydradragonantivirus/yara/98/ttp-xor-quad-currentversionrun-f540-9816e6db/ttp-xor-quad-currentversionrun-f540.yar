rule TTP_XOR_QUAD_CurrentVersionRun_f540 {
  strings:
    $key_f540 = { a6 2f [2] 82 21 [2] a9 0d [2] 87 2f [2] 93 34 [2] 9c 2e [2] 82 33 [2] 80 32 [2] 9b 34 [2] 87 33 [2] 9b 1c }

  condition:
    any of them
}