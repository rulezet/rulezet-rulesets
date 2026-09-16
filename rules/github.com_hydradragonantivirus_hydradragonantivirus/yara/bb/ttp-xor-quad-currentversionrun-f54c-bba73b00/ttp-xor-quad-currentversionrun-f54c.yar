rule TTP_XOR_QUAD_CurrentVersionRun_f54c {
  strings:
    $key_f54c = { a6 23 [2] 82 2d [2] a9 01 [2] 87 23 [2] 93 38 [2] 9c 22 [2] 82 3f [2] 80 3e [2] 9b 38 [2] 87 3f [2] 9b 10 }

  condition:
    any of them
}