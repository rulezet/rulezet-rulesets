rule TTP_XOR_QUAD_CurrentVersionRun_f55d {
  strings:
    $key_f55d = { a6 32 [2] 82 3c [2] a9 10 [2] 87 32 [2] 93 29 [2] 9c 33 [2] 82 2e [2] 80 2f [2] 9b 29 [2] 87 2e [2] 9b 01 }

  condition:
    any of them
}