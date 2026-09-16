rule TTP_XOR_QUAD_CurrentVersionRun_29c2 {
  strings:
    $key_29c2 = { 7a ad [2] 5e a3 [2] 75 8f [2] 5b ad [2] 4f b6 [2] 40 ac [2] 5e b1 [2] 5c b0 [2] 47 b6 [2] 5b b1 [2] 47 9e }

  condition:
    any of them
}