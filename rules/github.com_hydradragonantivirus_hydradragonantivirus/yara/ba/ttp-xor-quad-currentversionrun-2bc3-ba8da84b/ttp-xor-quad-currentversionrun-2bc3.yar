rule TTP_XOR_QUAD_CurrentVersionRun_2bc3 {
  strings:
    $key_2bc3 = { 78 ac [2] 5c a2 [2] 77 8e [2] 59 ac [2] 4d b7 [2] 42 ad [2] 5c b0 [2] 5e b1 [2] 45 b7 [2] 59 b0 [2] 45 9f }

  condition:
    any of them
}