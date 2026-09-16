rule TTP_XOR_QUAD_CurrentVersionRun_c4de {
  strings:
    $key_c4de = { 97 b1 [2] b3 bf [2] 98 93 [2] b6 b1 [2] a2 aa [2] ad b0 [2] b3 ad [2] b1 ac [2] aa aa [2] b6 ad [2] aa 82 }

  condition:
    any of them
}