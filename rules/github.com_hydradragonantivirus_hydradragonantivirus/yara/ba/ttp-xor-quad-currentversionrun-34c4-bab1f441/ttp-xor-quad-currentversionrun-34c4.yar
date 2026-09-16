rule TTP_XOR_QUAD_CurrentVersionRun_34c4 {
  strings:
    $key_34c4 = { 67 ab [2] 43 a5 [2] 68 89 [2] 46 ab [2] 52 b0 [2] 5d aa [2] 43 b7 [2] 41 b6 [2] 5a b0 [2] 46 b7 [2] 5a 98 }

  condition:
    any of them
}