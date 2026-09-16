rule TTP_XOR_QUAD_CurrentVersionRun_f048 {
  strings:
    $key_f048 = { a3 27 [2] 87 29 [2] ac 05 [2] 82 27 [2] 96 3c [2] 99 26 [2] 87 3b [2] 85 3a [2] 9e 3c [2] 82 3b [2] 9e 14 }

  condition:
    any of them
}