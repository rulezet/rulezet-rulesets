rule TTP_XOR_QUAD_CurrentVersionRun_e8d2 {
  strings:
    $key_e8d2 = { bb bd [2] 9f b3 [2] b4 9f [2] 9a bd [2] 8e a6 [2] 81 bc [2] 9f a1 [2] 9d a0 [2] 86 a6 [2] 9a a1 [2] 86 8e }

  condition:
    any of them
}