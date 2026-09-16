rule TTP_XOR_QUAD_CurrentVersionRun_44de {
  strings:
    $key_44de = { 17 b1 [2] 33 bf [2] 18 93 [2] 36 b1 [2] 22 aa [2] 2d b0 [2] 33 ad [2] 31 ac [2] 2a aa [2] 36 ad [2] 2a 82 }

  condition:
    any of them
}