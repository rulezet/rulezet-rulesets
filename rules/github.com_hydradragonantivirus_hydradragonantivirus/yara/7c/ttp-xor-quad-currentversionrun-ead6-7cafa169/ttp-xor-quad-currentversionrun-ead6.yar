rule TTP_XOR_QUAD_CurrentVersionRun_ead6 {
  strings:
    $key_ead6 = { b9 b9 [2] 9d b7 [2] b6 9b [2] 98 b9 [2] 8c a2 [2] 83 b8 [2] 9d a5 [2] 9f a4 [2] 84 a2 [2] 98 a5 [2] 84 8a }

  condition:
    any of them
}