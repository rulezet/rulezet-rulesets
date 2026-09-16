rule TTP_XOR_QUAD_CurrentVersionRun_0fc4 {
  strings:
    $key_0fc4 = { 5c ab [2] 78 a5 [2] 53 89 [2] 7d ab [2] 69 b0 [2] 66 aa [2] 78 b7 [2] 7a b6 [2] 61 b0 [2] 7d b7 [2] 61 98 }

  condition:
    any of them
}