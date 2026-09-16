rule TTP_XOR_QUAD_CurrentVersionRun_e7d2 {
  strings:
    $key_e7d2 = { b4 bd [2] 90 b3 [2] bb 9f [2] 95 bd [2] 81 a6 [2] 8e bc [2] 90 a1 [2] 92 a0 [2] 89 a6 [2] 95 a1 [2] 89 8e }

  condition:
    any of them
}