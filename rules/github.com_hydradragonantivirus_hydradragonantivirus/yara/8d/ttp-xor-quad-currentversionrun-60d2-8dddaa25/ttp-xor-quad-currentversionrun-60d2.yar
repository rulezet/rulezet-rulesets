rule TTP_XOR_QUAD_CurrentVersionRun_60d2 {
  strings:
    $key_60d2 = { 33 bd [2] 17 b3 [2] 3c 9f [2] 12 bd [2] 06 a6 [2] 09 bc [2] 17 a1 [2] 15 a0 [2] 0e a6 [2] 12 a1 [2] 0e 8e }

  condition:
    any of them
}