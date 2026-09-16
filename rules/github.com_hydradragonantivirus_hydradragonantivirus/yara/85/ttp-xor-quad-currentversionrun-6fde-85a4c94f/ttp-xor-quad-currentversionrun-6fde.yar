rule TTP_XOR_QUAD_CurrentVersionRun_6fde {
  strings:
    $key_6fde = { 3c b1 [2] 18 bf [2] 33 93 [2] 1d b1 [2] 09 aa [2] 06 b0 [2] 18 ad [2] 1a ac [2] 01 aa [2] 1d ad [2] 01 82 }

  condition:
    any of them
}