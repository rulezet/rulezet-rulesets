rule TTP_XOR_QUAD_CurrentVersionRun_edc5 {
  strings:
    $key_edc5 = { be aa [2] 9a a4 [2] b1 88 [2] 9f aa [2] 8b b1 [2] 84 ab [2] 9a b6 [2] 98 b7 [2] 83 b1 [2] 9f b6 [2] 83 99 }

  condition:
    any of them
}