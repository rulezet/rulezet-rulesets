rule TTP_XOR_QUAD_CurrentVersionRun_d1de {
  strings:
    $key_d1de = { 82 b1 [2] a6 bf [2] 8d 93 [2] a3 b1 [2] b7 aa [2] b8 b0 [2] a6 ad [2] a4 ac [2] bf aa [2] a3 ad [2] bf 82 }

  condition:
    any of them
}