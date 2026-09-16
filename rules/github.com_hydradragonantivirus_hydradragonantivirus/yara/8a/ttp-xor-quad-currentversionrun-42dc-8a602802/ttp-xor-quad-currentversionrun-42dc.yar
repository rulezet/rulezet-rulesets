rule TTP_XOR_QUAD_CurrentVersionRun_42dc {
  strings:
    $key_42dc = { 11 b3 [2] 35 bd [2] 1e 91 [2] 30 b3 [2] 24 a8 [2] 2b b2 [2] 35 af [2] 37 ae [2] 2c a8 [2] 30 af [2] 2c 80 }

  condition:
    any of them
}