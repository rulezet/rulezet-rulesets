rule TTP_XOR_QUAD_CurrentVersionRun_f7d7 {
  strings:
    $key_f7d7 = { a4 b8 [2] 80 b6 [2] ab 9a [2] 85 b8 [2] 91 a3 [2] 9e b9 [2] 80 a4 [2] 82 a5 [2] 99 a3 [2] 85 a4 [2] 99 8b }

  condition:
    any of them
}