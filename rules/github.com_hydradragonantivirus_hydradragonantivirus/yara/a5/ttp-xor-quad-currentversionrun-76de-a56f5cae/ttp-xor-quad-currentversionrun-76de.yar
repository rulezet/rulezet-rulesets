rule TTP_XOR_QUAD_CurrentVersionRun_76de {
  strings:
    $key_76de = { 25 b1 [2] 01 bf [2] 2a 93 [2] 04 b1 [2] 10 aa [2] 1f b0 [2] 01 ad [2] 03 ac [2] 18 aa [2] 04 ad [2] 18 82 }

  condition:
    any of them
}