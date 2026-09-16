rule TTP_XOR_QUAD_CurrentVersionRun_f545 {
  strings:
    $key_f545 = { a6 2a [2] 82 24 [2] a9 08 [2] 87 2a [2] 93 31 [2] 9c 2b [2] 82 36 [2] 80 37 [2] 9b 31 [2] 87 36 [2] 9b 19 }

  condition:
    any of them
}