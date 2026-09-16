rule TTP_XOR_QUAD_CurrentVersionRun_f5de {
  strings:
    $key_f5de = { a6 b1 [2] 82 bf [2] a9 93 [2] 87 b1 [2] 93 aa [2] 9c b0 [2] 82 ad [2] 80 ac [2] 9b aa [2] 87 ad [2] 9b 82 }

  condition:
    any of them
}