rule TTP_XOR_QUAD_CurrentVersionRun_e8c7 {
  strings:
    $key_e8c7 = { bb a8 [2] 9f a6 [2] b4 8a [2] 9a a8 [2] 8e b3 [2] 81 a9 [2] 9f b4 [2] 9d b5 [2] 86 b3 [2] 9a b4 [2] 86 9b }

  condition:
    any of them
}