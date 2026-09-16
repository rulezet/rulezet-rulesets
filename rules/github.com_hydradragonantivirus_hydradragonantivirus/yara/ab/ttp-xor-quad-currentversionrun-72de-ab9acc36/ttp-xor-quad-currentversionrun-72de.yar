rule TTP_XOR_QUAD_CurrentVersionRun_72de {
  strings:
    $key_72de = { 21 b1 [2] 05 bf [2] 2e 93 [2] 00 b1 [2] 14 aa [2] 1b b0 [2] 05 ad [2] 07 ac [2] 1c aa [2] 00 ad [2] 1c 82 }

  condition:
    any of them
}