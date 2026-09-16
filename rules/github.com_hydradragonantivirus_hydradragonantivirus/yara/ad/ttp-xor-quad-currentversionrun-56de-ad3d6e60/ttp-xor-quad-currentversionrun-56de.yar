rule TTP_XOR_QUAD_CurrentVersionRun_56de {
  strings:
    $key_56de = { 05 b1 [2] 21 bf [2] 0a 93 [2] 24 b1 [2] 30 aa [2] 3f b0 [2] 21 ad [2] 23 ac [2] 38 aa [2] 24 ad [2] 38 82 }

  condition:
    any of them
}