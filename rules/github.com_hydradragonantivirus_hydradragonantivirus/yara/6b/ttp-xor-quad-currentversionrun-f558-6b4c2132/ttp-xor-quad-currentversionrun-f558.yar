rule TTP_XOR_QUAD_CurrentVersionRun_f558 {
  strings:
    $key_f558 = { a6 37 [2] 82 39 [2] a9 15 [2] 87 37 [2] 93 2c [2] 9c 36 [2] 82 2b [2] 80 2a [2] 9b 2c [2] 87 2b [2] 9b 04 }

  condition:
    any of them
}