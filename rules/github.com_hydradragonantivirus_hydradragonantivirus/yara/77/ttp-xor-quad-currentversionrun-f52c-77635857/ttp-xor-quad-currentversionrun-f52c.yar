rule TTP_XOR_QUAD_CurrentVersionRun_f52c {
  strings:
    $key_f52c = { a6 43 [2] 82 4d [2] a9 61 [2] 87 43 [2] 93 58 [2] 9c 42 [2] 82 5f [2] 80 5e [2] 9b 58 [2] 87 5f [2] 9b 70 }

  condition:
    any of them
}