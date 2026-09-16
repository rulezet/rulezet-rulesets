rule TTP_XOR_QUAD_CurrentVersionRun_f56a {
  strings:
    $key_f56a = { a6 05 [2] 82 0b [2] a9 27 [2] 87 05 [2] 93 1e [2] 9c 04 [2] 82 19 [2] 80 18 [2] 9b 1e [2] 87 19 [2] 9b 36 }

  condition:
    any of them
}