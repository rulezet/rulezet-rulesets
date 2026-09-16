rule TTP_XOR_QUAD_CurrentVersionRun_d2de {
  strings:
    $key_d2de = { 81 b1 [2] a5 bf [2] 8e 93 [2] a0 b1 [2] b4 aa [2] bb b0 [2] a5 ad [2] a7 ac [2] bc aa [2] a0 ad [2] bc 82 }

  condition:
    any of them
}