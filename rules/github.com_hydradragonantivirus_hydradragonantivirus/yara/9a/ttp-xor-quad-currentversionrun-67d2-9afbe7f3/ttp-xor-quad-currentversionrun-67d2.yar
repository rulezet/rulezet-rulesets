rule TTP_XOR_QUAD_CurrentVersionRun_67d2 {
  strings:
    $key_67d2 = { 34 bd [2] 10 b3 [2] 3b 9f [2] 15 bd [2] 01 a6 [2] 0e bc [2] 10 a1 [2] 12 a0 [2] 09 a6 [2] 15 a1 [2] 09 8e }

  condition:
    any of them
}