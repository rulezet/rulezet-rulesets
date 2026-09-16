rule TTP_XOR_QUAD_CurrentVersionRun_fbd2 {
  strings:
    $key_fbd2 = { a8 bd [2] 8c b3 [2] a7 9f [2] 89 bd [2] 9d a6 [2] 92 bc [2] 8c a1 [2] 8e a0 [2] 95 a6 [2] 89 a1 [2] 95 8e }

  condition:
    any of them
}