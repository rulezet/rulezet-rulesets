rule TTP_XOR_QUAD_CurrentVersionRun_5ede {
  strings:
    $key_5ede = { 0d b1 [2] 29 bf [2] 02 93 [2] 2c b1 [2] 38 aa [2] 37 b0 [2] 29 ad [2] 2b ac [2] 30 aa [2] 2c ad [2] 30 82 }

  condition:
    any of them
}