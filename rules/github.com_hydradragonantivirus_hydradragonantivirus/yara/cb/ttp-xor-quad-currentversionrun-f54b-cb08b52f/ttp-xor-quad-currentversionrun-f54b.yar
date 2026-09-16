rule TTP_XOR_QUAD_CurrentVersionRun_f54b {
  strings:
    $key_f54b = { a6 24 [2] 82 2a [2] a9 06 [2] 87 24 [2] 93 3f [2] 9c 25 [2] 82 38 [2] 80 39 [2] 9b 3f [2] 87 38 [2] 9b 17 }

  condition:
    any of them
}