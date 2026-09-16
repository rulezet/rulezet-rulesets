rule TTP_XOR_QUAD_CurrentVersionRun_76d2 {
  strings:
    $key_76d2 = { 25 bd [2] 01 b3 [2] 2a 9f [2] 04 bd [2] 10 a6 [2] 1f bc [2] 01 a1 [2] 03 a0 [2] 18 a6 [2] 04 a1 [2] 18 8e }

  condition:
    any of them
}