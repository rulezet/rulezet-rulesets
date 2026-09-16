rule TTP_XOR_QUAD_CurrentVersionRun_f54a {
  strings:
    $key_f54a = { a6 25 [2] 82 2b [2] a9 07 [2] 87 25 [2] 93 3e [2] 9c 24 [2] 82 39 [2] 80 38 [2] 9b 3e [2] 87 39 [2] 9b 16 }

  condition:
    any of them
}