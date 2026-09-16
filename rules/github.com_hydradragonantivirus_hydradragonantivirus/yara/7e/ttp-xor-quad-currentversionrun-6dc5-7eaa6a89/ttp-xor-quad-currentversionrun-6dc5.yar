rule TTP_XOR_QUAD_CurrentVersionRun_6dc5 {
  strings:
    $key_6dc5 = { 3e aa [2] 1a a4 [2] 31 88 [2] 1f aa [2] 0b b1 [2] 04 ab [2] 1a b6 [2] 18 b7 [2] 03 b1 [2] 1f b6 [2] 03 99 }

  condition:
    any of them
}