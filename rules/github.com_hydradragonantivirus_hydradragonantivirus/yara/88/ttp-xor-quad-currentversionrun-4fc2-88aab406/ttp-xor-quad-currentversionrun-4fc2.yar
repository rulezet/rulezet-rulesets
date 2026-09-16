rule TTP_XOR_QUAD_CurrentVersionRun_4fc2 {
  strings:
    $key_4fc2 = { 1c ad [2] 38 a3 [2] 13 8f [2] 3d ad [2] 29 b6 [2] 26 ac [2] 38 b1 [2] 3a b0 [2] 21 b6 [2] 3d b1 [2] 21 9e }

  condition:
    any of them
}