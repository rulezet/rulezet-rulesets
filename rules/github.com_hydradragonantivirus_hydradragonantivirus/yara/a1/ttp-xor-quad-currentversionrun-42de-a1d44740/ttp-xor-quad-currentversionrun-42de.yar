rule TTP_XOR_QUAD_CurrentVersionRun_42de {
  strings:
    $key_42de = { 11 b1 [2] 35 bf [2] 1e 93 [2] 30 b1 [2] 24 aa [2] 2b b0 [2] 35 ad [2] 37 ac [2] 2c aa [2] 30 ad [2] 2c 82 }

  condition:
    any of them
}