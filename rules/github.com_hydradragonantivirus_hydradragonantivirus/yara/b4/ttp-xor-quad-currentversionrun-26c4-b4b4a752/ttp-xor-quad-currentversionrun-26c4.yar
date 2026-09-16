rule TTP_XOR_QUAD_CurrentVersionRun_26c4 {
  strings:
    $key_26c4 = { 75 ab [2] 51 a5 [2] 7a 89 [2] 54 ab [2] 40 b0 [2] 4f aa [2] 51 b7 [2] 53 b6 [2] 48 b0 [2] 54 b7 [2] 48 98 }

  condition:
    any of them
}