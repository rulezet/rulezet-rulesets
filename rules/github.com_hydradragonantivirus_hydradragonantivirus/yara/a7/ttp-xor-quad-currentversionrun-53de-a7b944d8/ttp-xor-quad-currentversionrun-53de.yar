rule TTP_XOR_QUAD_CurrentVersionRun_53de {
  strings:
    $key_53de = { 00 b1 [2] 24 bf [2] 0f 93 [2] 21 b1 [2] 35 aa [2] 3a b0 [2] 24 ad [2] 26 ac [2] 3d aa [2] 21 ad [2] 3d 82 }

  condition:
    any of them
}