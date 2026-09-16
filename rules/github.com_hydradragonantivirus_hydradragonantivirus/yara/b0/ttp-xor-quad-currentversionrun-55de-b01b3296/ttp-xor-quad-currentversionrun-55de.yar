rule TTP_XOR_QUAD_CurrentVersionRun_55de {
  strings:
    $key_55de = { 06 b1 [2] 22 bf [2] 09 93 [2] 27 b1 [2] 33 aa [2] 3c b0 [2] 22 ad [2] 20 ac [2] 3b aa [2] 27 ad [2] 3b 82 }

  condition:
    any of them
}