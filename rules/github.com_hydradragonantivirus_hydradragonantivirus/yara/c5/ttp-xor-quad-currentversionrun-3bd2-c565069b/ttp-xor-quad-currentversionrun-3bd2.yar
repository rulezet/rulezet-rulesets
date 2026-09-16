rule TTP_XOR_QUAD_CurrentVersionRun_3bd2 {
  strings:
    $key_3bd2 = { 68 bd [2] 4c b3 [2] 67 9f [2] 49 bd [2] 5d a6 [2] 52 bc [2] 4c a1 [2] 4e a0 [2] 55 a6 [2] 49 a1 [2] 55 8e }

  condition:
    any of them
}