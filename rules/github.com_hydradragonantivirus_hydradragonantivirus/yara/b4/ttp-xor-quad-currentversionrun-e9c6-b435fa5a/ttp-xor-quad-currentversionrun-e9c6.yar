rule TTP_XOR_QUAD_CurrentVersionRun_e9c6 {
  strings:
    $key_e9c6 = { ba a9 [2] 9e a7 [2] b5 8b [2] 9b a9 [2] 8f b2 [2] 80 a8 [2] 9e b5 [2] 9c b4 [2] 87 b2 [2] 9b b5 [2] 87 9a }

  condition:
    any of them
}