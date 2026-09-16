rule TTP_XOR_QUAD_CurrentVersionRun_16de {
  strings:
    $key_16de = { 45 b1 [2] 61 bf [2] 4a 93 [2] 64 b1 [2] 70 aa [2] 7f b0 [2] 61 ad [2] 63 ac [2] 78 aa [2] 64 ad [2] 78 82 }

  condition:
    any of them
}