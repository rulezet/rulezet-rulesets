rule TTP_XOR_QUAD_CurrentVersionRun_ebc6 {
  strings:
    $key_ebc6 = { b8 a9 [2] 9c a7 [2] b7 8b [2] 99 a9 [2] 8d b2 [2] 82 a8 [2] 9c b5 [2] 9e b4 [2] 85 b2 [2] 99 b5 [2] 85 9a }

  condition:
    any of them
}