rule TTP_XOR_QUAD_CurrentVersionRun_7fde {
  strings:
    $key_7fde = { 2c b1 [2] 08 bf [2] 23 93 [2] 0d b1 [2] 19 aa [2] 16 b0 [2] 08 ad [2] 0a ac [2] 11 aa [2] 0d ad [2] 11 82 }

  condition:
    any of them
}