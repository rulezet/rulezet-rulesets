rule TTP_XOR_QUAD_CurrentVersionRun_74de {
  strings:
    $key_74de = { 27 b1 [2] 03 bf [2] 28 93 [2] 06 b1 [2] 12 aa [2] 1d b0 [2] 03 ad [2] 01 ac [2] 1a aa [2] 06 ad [2] 1a 82 }

  condition:
    any of them
}