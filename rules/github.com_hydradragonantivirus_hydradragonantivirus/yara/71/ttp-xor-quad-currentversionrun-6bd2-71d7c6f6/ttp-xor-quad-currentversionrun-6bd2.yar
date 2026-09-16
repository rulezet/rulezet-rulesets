rule TTP_XOR_QUAD_CurrentVersionRun_6bd2 {
  strings:
    $key_6bd2 = { 38 bd [2] 1c b3 [2] 37 9f [2] 19 bd [2] 0d a6 [2] 02 bc [2] 1c a1 [2] 1e a0 [2] 05 a6 [2] 19 a1 [2] 05 8e }

  condition:
    any of them
}