rule TTP_XOR_QUAD_CurrentVersionRun_14d2 {
  strings:
    $key_14d2 = { 47 bd [2] 63 b3 [2] 48 9f [2] 66 bd [2] 72 a6 [2] 7d bc [2] 63 a1 [2] 61 a0 [2] 7a a6 [2] 66 a1 [2] 7a 8e }

  condition:
    any of them
}