rule TTP_XOR_QUAD_CurrentVersionRun_f8d6 {
  strings:
    $key_f8d6 = { ab b9 [2] 8f b7 [2] a4 9b [2] 8a b9 [2] 9e a2 [2] 91 b8 [2] 8f a5 [2] 8d a4 [2] 96 a2 [2] 8a a5 [2] 96 8a }

  condition:
    any of them
}