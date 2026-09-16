rule TTP_XOR_QUAD_CurrentVersionRun_0bd2 {
  strings:
    $key_0bd2 = { 58 bd [2] 7c b3 [2] 57 9f [2] 79 bd [2] 6d a6 [2] 62 bc [2] 7c a1 [2] 7e a0 [2] 65 a6 [2] 79 a1 [2] 65 8e }

  condition:
    any of them
}