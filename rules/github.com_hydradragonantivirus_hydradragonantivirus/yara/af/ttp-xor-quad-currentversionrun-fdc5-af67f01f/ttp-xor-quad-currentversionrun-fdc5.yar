rule TTP_XOR_QUAD_CurrentVersionRun_fdc5 {
  strings:
    $key_fdc5 = { ae aa [2] 8a a4 [2] a1 88 [2] 8f aa [2] 9b b1 [2] 94 ab [2] 8a b6 [2] 88 b7 [2] 93 b1 [2] 8f b6 [2] 93 99 }

  condition:
    any of them
}