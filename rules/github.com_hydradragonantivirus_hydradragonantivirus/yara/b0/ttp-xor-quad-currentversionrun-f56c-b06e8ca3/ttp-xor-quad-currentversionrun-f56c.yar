rule TTP_XOR_QUAD_CurrentVersionRun_f56c {
  strings:
    $key_f56c = { a6 03 [2] 82 0d [2] a9 21 [2] 87 03 [2] 93 18 [2] 9c 02 [2] 82 1f [2] 80 1e [2] 9b 18 [2] 87 1f [2] 9b 30 }

  condition:
    any of them
}