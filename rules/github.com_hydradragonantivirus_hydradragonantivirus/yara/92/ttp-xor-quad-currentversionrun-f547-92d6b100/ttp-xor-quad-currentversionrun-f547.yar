rule TTP_XOR_QUAD_CurrentVersionRun_f547 {
  strings:
    $key_f547 = { a6 28 [2] 82 26 [2] a9 0a [2] 87 28 [2] 93 33 [2] 9c 29 [2] 82 34 [2] 80 35 [2] 9b 33 [2] 87 34 [2] 9b 1b }

  condition:
    any of them
}