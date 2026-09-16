rule TTP_XOR_QUAD_CurrentVersionRun_e7de {
  strings:
    $key_e7de = { b4 b1 [2] 90 bf [2] bb 93 [2] 95 b1 [2] 81 aa [2] 8e b0 [2] 90 ad [2] 92 ac [2] 89 aa [2] 95 ad [2] 89 82 }

  condition:
    any of them
}