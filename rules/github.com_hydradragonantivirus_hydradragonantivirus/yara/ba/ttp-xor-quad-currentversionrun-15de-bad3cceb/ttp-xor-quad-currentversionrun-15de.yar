rule TTP_XOR_QUAD_CurrentVersionRun_15de {
  strings:
    $key_15de = { 46 b1 [2] 62 bf [2] 49 93 [2] 67 b1 [2] 73 aa [2] 7c b0 [2] 62 ad [2] 60 ac [2] 7b aa [2] 67 ad [2] 7b 82 }

  condition:
    any of them
}