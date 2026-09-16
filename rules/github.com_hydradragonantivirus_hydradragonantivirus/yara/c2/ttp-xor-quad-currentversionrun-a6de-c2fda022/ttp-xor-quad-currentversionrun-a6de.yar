rule TTP_XOR_QUAD_CurrentVersionRun_a6de {
  strings:
    $key_a6de = { f5 b1 [2] d1 bf [2] fa 93 [2] d4 b1 [2] c0 aa [2] cf b0 [2] d1 ad [2] d3 ac [2] c8 aa [2] d4 ad [2] c8 82 }

  condition:
    any of them
}