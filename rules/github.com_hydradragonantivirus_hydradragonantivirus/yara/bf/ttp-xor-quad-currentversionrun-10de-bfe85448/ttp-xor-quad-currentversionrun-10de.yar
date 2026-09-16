rule TTP_XOR_QUAD_CurrentVersionRun_10de {
  strings:
    $key_10de = { 43 b1 [2] 67 bf [2] 4c 93 [2] 62 b1 [2] 76 aa [2] 79 b0 [2] 67 ad [2] 65 ac [2] 7e aa [2] 62 ad [2] 7e 82 }

  condition:
    any of them
}