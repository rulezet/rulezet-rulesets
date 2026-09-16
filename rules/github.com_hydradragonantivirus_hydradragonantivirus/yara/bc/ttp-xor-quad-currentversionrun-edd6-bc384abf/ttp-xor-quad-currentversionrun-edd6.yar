rule TTP_XOR_QUAD_CurrentVersionRun_edd6 {
  strings:
    $key_edd6 = { be b9 [2] 9a b7 [2] b1 9b [2] 9f b9 [2] 8b a2 [2] 84 b8 [2] 9a a5 [2] 98 a4 [2] 83 a2 [2] 9f a5 [2] 83 8a }

  condition:
    any of them
}