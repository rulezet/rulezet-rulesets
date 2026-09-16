rule TTP_XOR_QUAD_CurrentVersionRun_63de {
  strings:
    $key_63de = { 30 b1 [2] 14 bf [2] 3f 93 [2] 11 b1 [2] 05 aa [2] 0a b0 [2] 14 ad [2] 16 ac [2] 0d aa [2] 11 ad [2] 0d 82 }

  condition:
    any of them
}