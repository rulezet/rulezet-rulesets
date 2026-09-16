rule TTP_XOR_QUAD_CurrentVersionRun_ebc2 {
  strings:
    $key_ebc2 = { b8 ad [2] 9c a3 [2] b7 8f [2] 99 ad [2] 8d b6 [2] 82 ac [2] 9c b1 [2] 9e b0 [2] 85 b6 [2] 99 b1 [2] 85 9e }

  condition:
    any of them
}