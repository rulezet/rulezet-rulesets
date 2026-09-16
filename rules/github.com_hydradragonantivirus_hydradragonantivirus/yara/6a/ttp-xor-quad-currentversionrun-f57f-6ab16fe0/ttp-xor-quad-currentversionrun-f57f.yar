rule TTP_XOR_QUAD_CurrentVersionRun_f57f {
  strings:
    $key_f57f = { a6 10 [2] 82 1e [2] a9 32 [2] 87 10 [2] 93 0b [2] 9c 11 [2] 82 0c [2] 80 0d [2] 9b 0b [2] 87 0c [2] 9b 23 }

  condition:
    any of them
}