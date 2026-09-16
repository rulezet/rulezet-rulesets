rule TTP_XOR_QUAD_CurrentVersionRun_0dd6 {
  strings:
    $key_0dd6 = { 5e b9 [2] 7a b7 [2] 51 9b [2] 7f b9 [2] 6b a2 [2] 64 b8 [2] 7a a5 [2] 78 a4 [2] 63 a2 [2] 7f a5 [2] 63 8a }

  condition:
    any of them
}