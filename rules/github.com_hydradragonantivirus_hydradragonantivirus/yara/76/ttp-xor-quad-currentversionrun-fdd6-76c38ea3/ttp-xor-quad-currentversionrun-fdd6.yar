rule TTP_XOR_QUAD_CurrentVersionRun_fdd6 {
  strings:
    $key_fdd6 = { ae b9 [2] 8a b7 [2] a1 9b [2] 8f b9 [2] 9b a2 [2] 94 b8 [2] 8a a5 [2] 88 a4 [2] 93 a2 [2] 8f a5 [2] 93 8a }

  condition:
    any of them
}