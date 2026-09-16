rule TTP_XOR_QUAD_CurrentVersionRun_6bc2 {
  strings:
    $key_6bc2 = { 38 ad [2] 1c a3 [2] 37 8f [2] 19 ad [2] 0d b6 [2] 02 ac [2] 1c b1 [2] 1e b0 [2] 05 b6 [2] 19 b1 [2] 05 9e }

  condition:
    any of them
}