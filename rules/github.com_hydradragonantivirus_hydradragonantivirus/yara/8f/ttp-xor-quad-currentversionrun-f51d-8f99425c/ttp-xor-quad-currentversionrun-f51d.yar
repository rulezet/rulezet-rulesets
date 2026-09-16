rule TTP_XOR_QUAD_CurrentVersionRun_f51d {
  strings:
    $key_f51d = { a6 72 [2] 82 7c [2] a9 50 [2] 87 72 [2] 93 69 [2] 9c 73 [2] 82 6e [2] 80 6f [2] 9b 69 [2] 87 6e [2] 9b 41 }

  condition:
    any of them
}