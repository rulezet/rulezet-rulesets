rule TTP_XOR_QUAD_CurrentVersionRun_d3de {
  strings:
    $key_d3de = { 80 b1 [2] a4 bf [2] 8f 93 [2] a1 b1 [2] b5 aa [2] ba b0 [2] a4 ad [2] a6 ac [2] bd aa [2] a1 ad [2] bd 82 }

  condition:
    any of them
}