rule TTP_XOR_QUAD_CurrentVersionRun_f067 {
  strings:
    $key_f067 = { a3 08 [2] 87 06 [2] ac 2a [2] 82 08 [2] 96 13 [2] 99 09 [2] 87 14 [2] 85 15 [2] 9e 13 [2] 82 14 [2] 9e 3b }

  condition:
    any of them
}