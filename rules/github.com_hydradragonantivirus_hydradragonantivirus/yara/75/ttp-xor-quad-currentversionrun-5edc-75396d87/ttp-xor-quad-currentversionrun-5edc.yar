rule TTP_XOR_QUAD_CurrentVersionRun_5edc {
  strings:
    $key_5edc = { 0d b3 [2] 29 bd [2] 02 91 [2] 2c b3 [2] 38 a8 [2] 37 b2 [2] 29 af [2] 2b ae [2] 30 a8 [2] 2c af [2] 30 80 }

  condition:
    any of them
}