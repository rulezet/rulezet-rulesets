rule TTP_XOR_QUAD_CurrentVersionRun_31de {
  strings:
    $key_31de = { 62 b1 [2] 46 bf [2] 6d 93 [2] 43 b1 [2] 57 aa [2] 58 b0 [2] 46 ad [2] 44 ac [2] 5f aa [2] 43 ad [2] 5f 82 }

  condition:
    any of them
}