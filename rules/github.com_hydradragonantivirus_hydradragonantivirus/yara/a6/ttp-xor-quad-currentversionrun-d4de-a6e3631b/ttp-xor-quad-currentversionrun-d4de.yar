rule TTP_XOR_QUAD_CurrentVersionRun_d4de {
  strings:
    $key_d4de = { 87 b1 [2] a3 bf [2] 88 93 [2] a6 b1 [2] b2 aa [2] bd b0 [2] a3 ad [2] a1 ac [2] ba aa [2] a6 ad [2] ba 82 }

  condition:
    any of them
}