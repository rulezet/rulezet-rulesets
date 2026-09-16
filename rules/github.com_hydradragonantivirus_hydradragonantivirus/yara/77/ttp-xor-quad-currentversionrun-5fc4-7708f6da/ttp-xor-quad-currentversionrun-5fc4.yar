rule TTP_XOR_QUAD_CurrentVersionRun_5fc4 {
  strings:
    $key_5fc4 = { 0c ab [2] 28 a5 [2] 03 89 [2] 2d ab [2] 39 b0 [2] 36 aa [2] 28 b7 [2] 2a b6 [2] 31 b0 [2] 2d b7 [2] 31 98 }

  condition:
    any of them
}