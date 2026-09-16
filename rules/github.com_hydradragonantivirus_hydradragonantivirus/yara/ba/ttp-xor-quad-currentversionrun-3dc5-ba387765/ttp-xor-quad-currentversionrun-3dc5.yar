rule TTP_XOR_QUAD_CurrentVersionRun_3dc5 {
  strings:
    $key_3dc5 = { 6e aa [2] 4a a4 [2] 61 88 [2] 4f aa [2] 5b b1 [2] 54 ab [2] 4a b6 [2] 48 b7 [2] 53 b1 [2] 4f b6 [2] 53 99 }

  condition:
    any of them
}