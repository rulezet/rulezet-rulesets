rule TTP_XOR_QUAD_CurrentVersionRun_54d2 {
  strings:
    $key_54d2 = { 07 bd [2] 23 b3 [2] 08 9f [2] 26 bd [2] 32 a6 [2] 3d bc [2] 23 a1 [2] 21 a0 [2] 3a a6 [2] 26 a1 [2] 3a 8e }

  condition:
    any of them
}