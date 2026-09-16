rule TTP_XOR_QUAD_CurrentVersionRun_f7d5 {
  strings:
    $key_f7d5 = { a4 ba [2] 80 b4 [2] ab 98 [2] 85 ba [2] 91 a1 [2] 9e bb [2] 80 a6 [2] 82 a7 [2] 99 a1 [2] 85 a6 [2] 99 89 }

  condition:
    any of them
}