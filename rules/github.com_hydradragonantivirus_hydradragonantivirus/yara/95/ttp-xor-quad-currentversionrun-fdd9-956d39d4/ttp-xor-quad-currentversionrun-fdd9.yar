rule TTP_XOR_QUAD_CurrentVersionRun_fdd9 {
  strings:
    $key_fdd9 = { ae b6 [2] 8a b8 [2] a1 94 [2] 8f b6 [2] 9b ad [2] 94 b7 [2] 8a aa [2] 88 ab [2] 93 ad [2] 8f aa [2] 93 85 }

  condition:
    any of them
}