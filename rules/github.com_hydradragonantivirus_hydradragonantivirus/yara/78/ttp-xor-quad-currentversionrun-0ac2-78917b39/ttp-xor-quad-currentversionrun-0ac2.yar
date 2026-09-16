rule TTP_XOR_QUAD_CurrentVersionRun_0ac2 {
  strings:
    $key_0ac2 = { 59 ad [2] 7d a3 [2] 56 8f [2] 78 ad [2] 6c b6 [2] 63 ac [2] 7d b1 [2] 7f b0 [2] 64 b6 [2] 78 b1 [2] 64 9e }

  condition:
    any of them
}