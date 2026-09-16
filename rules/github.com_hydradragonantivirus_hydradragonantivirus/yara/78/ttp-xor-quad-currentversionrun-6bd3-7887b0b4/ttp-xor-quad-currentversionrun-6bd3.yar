rule TTP_XOR_QUAD_CurrentVersionRun_6bd3 {
  strings:
    $key_6bd3 = { 38 bc [2] 1c b2 [2] 37 9e [2] 19 bc [2] 0d a7 [2] 02 bd [2] 1c a0 [2] 1e a1 [2] 05 a7 [2] 19 a0 [2] 05 8f }

  condition:
    any of them
}