rule TTP_XOR_QUAD_CurrentVersionRun_c5de {
  strings:
    $key_c5de = { 96 b1 [2] b2 bf [2] 99 93 [2] b7 b1 [2] a3 aa [2] ac b0 [2] b2 ad [2] b0 ac [2] ab aa [2] b7 ad [2] ab 82 }

  condition:
    any of them
}