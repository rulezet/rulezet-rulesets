rule TTP_XOR_QUAD_CurrentVersionRun_f767 {
  strings:
    $key_f767 = { a4 08 [2] 80 06 [2] ab 2a [2] 85 08 [2] 91 13 [2] 9e 09 [2] 80 14 [2] 82 15 [2] 99 13 [2] 85 14 [2] 99 3b }

  condition:
    any of them
}