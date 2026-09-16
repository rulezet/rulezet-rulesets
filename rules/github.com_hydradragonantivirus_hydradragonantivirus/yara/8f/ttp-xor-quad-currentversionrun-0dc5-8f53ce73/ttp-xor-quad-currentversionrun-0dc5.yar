rule TTP_XOR_QUAD_CurrentVersionRun_0dc5 {
  strings:
    $key_0dc5 = { 5e aa [2] 7a a4 [2] 51 88 [2] 7f aa [2] 6b b1 [2] 64 ab [2] 7a b6 [2] 78 b7 [2] 63 b1 [2] 7f b6 [2] 63 99 }

  condition:
    any of them
}