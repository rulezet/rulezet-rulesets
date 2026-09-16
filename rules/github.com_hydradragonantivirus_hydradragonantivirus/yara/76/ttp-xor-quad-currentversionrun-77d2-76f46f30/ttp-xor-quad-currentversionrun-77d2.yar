rule TTP_XOR_QUAD_CurrentVersionRun_77d2 {
  strings:
    $key_77d2 = { 24 bd [2] 00 b3 [2] 2b 9f [2] 05 bd [2] 11 a6 [2] 1e bc [2] 00 a1 [2] 02 a0 [2] 19 a6 [2] 05 a1 [2] 19 8e }

  condition:
    any of them
}