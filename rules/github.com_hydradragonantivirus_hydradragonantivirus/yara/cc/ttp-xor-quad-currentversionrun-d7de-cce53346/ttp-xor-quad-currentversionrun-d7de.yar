rule TTP_XOR_QUAD_CurrentVersionRun_d7de {
  strings:
    $key_d7de = { 84 b1 [2] a0 bf [2] 8b 93 [2] a5 b1 [2] b1 aa [2] be b0 [2] a0 ad [2] a2 ac [2] b9 aa [2] a5 ad [2] b9 82 }

  condition:
    any of them
}