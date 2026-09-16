rule TTP_XOR_QUAD_CurrentVersionRun_b4de {
  strings:
    $key_b4de = { e7 b1 [2] c3 bf [2] e8 93 [2] c6 b1 [2] d2 aa [2] dd b0 [2] c3 ad [2] c1 ac [2] da aa [2] c6 ad [2] da 82 }

  condition:
    any of them
}