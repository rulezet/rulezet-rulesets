rule TTP_XOR_QUAD_CurrentVersionRun_f7d2 {
  strings:
    $key_f7d2 = { a4 bd [2] 80 b3 [2] ab 9f [2] 85 bd [2] 91 a6 [2] 9e bc [2] 80 a1 [2] 82 a0 [2] 99 a6 [2] 85 a1 [2] 99 8e }

  condition:
    any of them
}