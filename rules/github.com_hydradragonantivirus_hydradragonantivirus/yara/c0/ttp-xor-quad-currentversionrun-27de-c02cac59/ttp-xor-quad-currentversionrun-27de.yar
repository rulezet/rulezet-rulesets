rule TTP_XOR_QUAD_CurrentVersionRun_27de {
  strings:
    $key_27de = { 74 b1 [2] 50 bf [2] 7b 93 [2] 55 b1 [2] 41 aa [2] 4e b0 [2] 50 ad [2] 52 ac [2] 49 aa [2] 55 ad [2] 49 82 }

  condition:
    any of them
}