rule TTP_XOR_QUAD_CurrentVersionRun_52de {
  strings:
    $key_52de = { 01 b1 [2] 25 bf [2] 0e 93 [2] 20 b1 [2] 34 aa [2] 3b b0 [2] 25 ad [2] 27 ac [2] 3c aa [2] 20 ad [2] 3c 82 }

  condition:
    any of them
}