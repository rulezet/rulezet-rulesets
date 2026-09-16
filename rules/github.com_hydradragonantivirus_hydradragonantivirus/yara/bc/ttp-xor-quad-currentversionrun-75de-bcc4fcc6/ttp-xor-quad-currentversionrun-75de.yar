rule TTP_XOR_QUAD_CurrentVersionRun_75de {
  strings:
    $key_75de = { 26 b1 [2] 02 bf [2] 29 93 [2] 07 b1 [2] 13 aa [2] 1c b0 [2] 02 ad [2] 00 ac [2] 1b aa [2] 07 ad [2] 1b 82 }

  condition:
    any of them
}