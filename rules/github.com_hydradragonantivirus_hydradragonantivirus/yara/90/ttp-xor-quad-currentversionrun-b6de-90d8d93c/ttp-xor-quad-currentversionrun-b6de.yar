rule TTP_XOR_QUAD_CurrentVersionRun_b6de {
  strings:
    $key_b6de = { e5 b1 [2] c1 bf [2] ea 93 [2] c4 b1 [2] d0 aa [2] df b0 [2] c1 ad [2] c3 ac [2] d8 aa [2] c4 ad [2] d8 82 }

  condition:
    any of them
}