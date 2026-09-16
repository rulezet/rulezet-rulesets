rule TTP_XOR_QUAD_CurrentVersionRun_56d2 {
  strings:
    $key_56d2 = { 05 bd [2] 21 b3 [2] 0a 9f [2] 24 bd [2] 30 a6 [2] 3f bc [2] 21 a1 [2] 23 a0 [2] 38 a6 [2] 24 a1 [2] 38 8e }

  condition:
    any of them
}