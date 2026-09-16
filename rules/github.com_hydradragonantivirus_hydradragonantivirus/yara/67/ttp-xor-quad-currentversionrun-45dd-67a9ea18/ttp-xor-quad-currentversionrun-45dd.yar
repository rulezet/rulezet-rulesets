rule TTP_XOR_QUAD_CurrentVersionRun_45dd {
  strings:
    $key_45dd = { 16 b2 [2] 32 bc [2] 19 90 [2] 37 b2 [2] 23 a9 [2] 2c b3 [2] 32 ae [2] 30 af [2] 2b a9 [2] 37 ae [2] 2b 81 }

  condition:
    any of them
}