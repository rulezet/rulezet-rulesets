rule TTP_XOR_QUAD_CurrentVersionRun_4fc4 {
  strings:
    $key_4fc4 = { 1c ab [2] 38 a5 [2] 13 89 [2] 3d ab [2] 29 b0 [2] 26 aa [2] 38 b7 [2] 3a b6 [2] 21 b0 [2] 3d b7 [2] 21 98 }

  condition:
    any of them
}