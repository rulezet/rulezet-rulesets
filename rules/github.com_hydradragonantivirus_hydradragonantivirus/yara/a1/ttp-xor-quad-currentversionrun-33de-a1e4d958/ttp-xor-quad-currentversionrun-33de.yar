rule TTP_XOR_QUAD_CurrentVersionRun_33de {
  strings:
    $key_33de = { 60 b1 [2] 44 bf [2] 6f 93 [2] 41 b1 [2] 55 aa [2] 5a b0 [2] 44 ad [2] 46 ac [2] 5d aa [2] 41 ad [2] 5d 82 }

  condition:
    any of them
}