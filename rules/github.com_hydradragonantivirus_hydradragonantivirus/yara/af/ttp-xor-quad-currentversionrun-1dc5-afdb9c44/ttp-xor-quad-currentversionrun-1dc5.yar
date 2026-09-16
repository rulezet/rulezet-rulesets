rule TTP_XOR_QUAD_CurrentVersionRun_1dc5 {
  strings:
    $key_1dc5 = { 4e aa [2] 6a a4 [2] 41 88 [2] 6f aa [2] 7b b1 [2] 74 ab [2] 6a b6 [2] 68 b7 [2] 73 b1 [2] 6f b6 [2] 73 99 }

  condition:
    any of them
}