rule TTP_XOR_QUAD_CurrentVersionRun_50c3 {
  strings:
    $key_50c3 = { 03 ac [2] 27 a2 [2] 0c 8e [2] 22 ac [2] 36 b7 [2] 39 ad [2] 27 b0 [2] 25 b1 [2] 3e b7 [2] 22 b0 [2] 3e 9f }

  condition:
    any of them
}