rule TTP_XOR_QUAD_CurrentVersionRun_f079 {
  strings:
    $key_f079 = { a3 16 [2] 87 18 [2] ac 34 [2] 82 16 [2] 96 0d [2] 99 17 [2] 87 0a [2] 85 0b [2] 9e 0d [2] 82 0a [2] 9e 25 }

  condition:
    any of them
}