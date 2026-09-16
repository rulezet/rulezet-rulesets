rule TTP_XOR_QUAD_CurrentVersionRun_c0de {
  strings:
    $key_c0de = { 93 b1 [2] b7 bf [2] 9c 93 [2] b2 b1 [2] a6 aa [2] a9 b0 [2] b7 ad [2] b5 ac [2] ae aa [2] b2 ad [2] ae 82 }

  condition:
    any of them
}