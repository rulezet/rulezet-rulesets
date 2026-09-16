rule TTP_XOR_QUAD_CurrentVersionRun_f737 {
  strings:
    $key_f737 = { a4 58 [2] 80 56 [2] ab 7a [2] 85 58 [2] 91 43 [2] 9e 59 [2] 80 44 [2] 82 45 [2] 99 43 [2] 85 44 [2] 99 6b }

  condition:
    any of them
}