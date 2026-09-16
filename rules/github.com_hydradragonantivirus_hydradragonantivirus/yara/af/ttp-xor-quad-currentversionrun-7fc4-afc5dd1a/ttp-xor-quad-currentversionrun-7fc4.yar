rule TTP_XOR_QUAD_CurrentVersionRun_7fc4 {
  strings:
    $key_7fc4 = { 2c ab [2] 08 a5 [2] 23 89 [2] 0d ab [2] 19 b0 [2] 16 aa [2] 08 b7 [2] 0a b6 [2] 11 b0 [2] 0d b7 [2] 11 98 }

  condition:
    any of them
}