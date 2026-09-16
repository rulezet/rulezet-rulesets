rule TTP_XOR_QUAD_CurrentVersionRun_13de {
  strings:
    $key_13de = { 40 b1 [2] 64 bf [2] 4f 93 [2] 61 b1 [2] 75 aa [2] 7a b0 [2] 64 ad [2] 66 ac [2] 7d aa [2] 61 ad [2] 7d 82 }

  condition:
    any of them
}