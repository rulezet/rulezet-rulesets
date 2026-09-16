rule TTP_XOR_QUAD_CurrentVersionRun_35de {
  strings:
    $key_35de = { 66 b1 [2] 42 bf [2] 69 93 [2] 47 b1 [2] 53 aa [2] 5c b0 [2] 42 ad [2] 40 ac [2] 5b aa [2] 47 ad [2] 5b 82 }

  condition:
    any of them
}