rule TTP_XOR_QUAD_CurrentVersionRun_10c3 {
  strings:
    $key_10c3 = { 43 ac [2] 67 a2 [2] 4c 8e [2] 62 ac [2] 76 b7 [2] 79 ad [2] 67 b0 [2] 65 b1 [2] 7e b7 [2] 62 b0 [2] 7e 9f }

  condition:
    any of them
}