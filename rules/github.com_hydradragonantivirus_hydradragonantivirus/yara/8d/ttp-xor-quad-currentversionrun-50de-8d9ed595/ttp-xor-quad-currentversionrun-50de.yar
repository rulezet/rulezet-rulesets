rule TTP_XOR_QUAD_CurrentVersionRun_50de {
  strings:
    $key_50de = { 03 b1 [2] 27 bf [2] 0c 93 [2] 22 b1 [2] 36 aa [2] 39 b0 [2] 27 ad [2] 25 ac [2] 3e aa [2] 22 ad [2] 3e 82 }

  condition:
    any of them
}