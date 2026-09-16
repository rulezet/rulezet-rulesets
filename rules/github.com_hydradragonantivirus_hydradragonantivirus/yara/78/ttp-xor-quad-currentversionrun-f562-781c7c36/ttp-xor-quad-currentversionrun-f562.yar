rule TTP_XOR_QUAD_CurrentVersionRun_f562 {
  strings:
    $key_f562 = { a6 0d [2] 82 03 [2] a9 2f [2] 87 0d [2] 93 16 [2] 9c 0c [2] 82 11 [2] 80 10 [2] 9b 16 [2] 87 11 [2] 9b 3e }

  condition:
    any of them
}