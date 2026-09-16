rule TTP_XOR_QUAD_CurrentVersionRun_f074 {
  strings:
    $key_f074 = { a3 1b [2] 87 15 [2] ac 39 [2] 82 1b [2] 96 00 [2] 99 1a [2] 87 07 [2] 85 06 [2] 9e 00 [2] 82 07 [2] 9e 28 }

  condition:
    any of them
}