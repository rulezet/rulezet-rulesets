rule TTP_XOR_QUAD_CurrentVersionRun_01de {
  strings:
    $key_01de = { 52 b1 [2] 76 bf [2] 5d 93 [2] 73 b1 [2] 67 aa [2] 68 b0 [2] 76 ad [2] 74 ac [2] 6f aa [2] 73 ad [2] 6f 82 }

  condition:
    any of them
}