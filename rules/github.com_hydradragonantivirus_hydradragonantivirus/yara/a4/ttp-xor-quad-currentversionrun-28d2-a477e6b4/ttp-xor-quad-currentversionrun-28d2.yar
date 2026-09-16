rule TTP_XOR_QUAD_CurrentVersionRun_28d2 {
  strings:
    $key_28d2 = { 7b bd [2] 5f b3 [2] 74 9f [2] 5a bd [2] 4e a6 [2] 41 bc [2] 5f a1 [2] 5d a0 [2] 46 a6 [2] 5a a1 [2] 46 8e }

  condition:
    any of them
}