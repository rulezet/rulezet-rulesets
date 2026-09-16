rule TTP_XOR_QUAD_CurrentVersionRun_f075 {
  strings:
    $key_f075 = { a3 1a [2] 87 14 [2] ac 38 [2] 82 1a [2] 96 01 [2] 99 1b [2] 87 06 [2] 85 07 [2] 9e 01 [2] 82 06 [2] 9e 29 }

  condition:
    any of them
}