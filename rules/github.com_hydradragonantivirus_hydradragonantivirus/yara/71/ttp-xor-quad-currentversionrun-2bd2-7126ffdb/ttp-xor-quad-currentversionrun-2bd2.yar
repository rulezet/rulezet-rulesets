rule TTP_XOR_QUAD_CurrentVersionRun_2bd2 {
  strings:
    $key_2bd2 = { 78 bd [2] 5c b3 [2] 77 9f [2] 59 bd [2] 4d a6 [2] 42 bc [2] 5c a1 [2] 5e a0 [2] 45 a6 [2] 59 a1 [2] 45 8e }

  condition:
    any of them
}