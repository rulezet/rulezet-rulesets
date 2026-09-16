rule TTP_XOR_QUAD_CurrentVersionRun_f574 {
  strings:
    $key_f574 = { a6 1b [2] 82 15 [2] a9 39 [2] 87 1b [2] 93 00 [2] 9c 1a [2] 82 07 [2] 80 06 [2] 9b 00 [2] 87 07 [2] 9b 28 }

  condition:
    any of them
}