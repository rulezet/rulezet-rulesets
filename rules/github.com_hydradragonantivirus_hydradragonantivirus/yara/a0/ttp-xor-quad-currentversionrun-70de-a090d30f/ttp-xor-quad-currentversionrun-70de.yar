rule TTP_XOR_QUAD_CurrentVersionRun_70de {
  strings:
    $key_70de = { 23 b1 [2] 07 bf [2] 2c 93 [2] 02 b1 [2] 16 aa [2] 19 b0 [2] 07 ad [2] 05 ac [2] 1e aa [2] 02 ad [2] 1e 82 }

  condition:
    any of them
}