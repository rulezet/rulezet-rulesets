rule TTP_XOR_QUAD_CurrentVersionRun_f54d {
  strings:
    $key_f54d = { a6 22 [2] 82 2c [2] a9 00 [2] 87 22 [2] 93 39 [2] 9c 23 [2] 82 3e [2] 80 3f [2] 9b 39 [2] 87 3e [2] 9b 11 }

  condition:
    any of them
}