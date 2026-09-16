rule TTP_XOR_QUAD_CurrentVersionRun_a1de {
  strings:
    $key_a1de = { f2 b1 [2] d6 bf [2] fd 93 [2] d3 b1 [2] c7 aa [2] c8 b0 [2] d6 ad [2] d4 ac [2] cf aa [2] d3 ad [2] cf 82 }

  condition:
    any of them
}