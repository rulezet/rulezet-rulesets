rule TTP_XOR_QUAD_CurrentVersionRun_07de {
  strings:
    $key_07de = { 54 b1 [2] 70 bf [2] 5b 93 [2] 75 b1 [2] 61 aa [2] 6e b0 [2] 70 ad [2] 72 ac [2] 69 aa [2] 75 ad [2] 69 82 }

  condition:
    any of them
}