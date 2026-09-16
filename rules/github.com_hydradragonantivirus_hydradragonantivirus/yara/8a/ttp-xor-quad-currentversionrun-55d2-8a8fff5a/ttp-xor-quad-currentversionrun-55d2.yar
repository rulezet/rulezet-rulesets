rule TTP_XOR_QUAD_CurrentVersionRun_55d2 {
  strings:
    $key_55d2 = { 06 bd [2] 22 b3 [2] 09 9f [2] 27 bd [2] 33 a6 [2] 3c bc [2] 22 a1 [2] 20 a0 [2] 3b a6 [2] 27 a1 [2] 3b 8e }

  condition:
    any of them
}