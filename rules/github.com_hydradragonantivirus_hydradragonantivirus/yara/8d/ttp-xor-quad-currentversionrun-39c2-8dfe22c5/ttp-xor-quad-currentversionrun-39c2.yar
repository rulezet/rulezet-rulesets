rule TTP_XOR_QUAD_CurrentVersionRun_39c2 {
  strings:
    $key_39c2 = { 6a ad [2] 4e a3 [2] 65 8f [2] 4b ad [2] 5f b6 [2] 50 ac [2] 4e b1 [2] 4c b0 [2] 57 b6 [2] 4b b1 [2] 57 9e }

  condition:
    any of them
}