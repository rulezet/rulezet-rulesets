rule TTP_XOR_QUAD_CurrentVersionRun_a3de {
  strings:
    $key_a3de = { f0 b1 [2] d4 bf [2] ff 93 [2] d1 b1 [2] c5 aa [2] ca b0 [2] d4 ad [2] d6 ac [2] cd aa [2] d1 ad [2] cd 82 }

  condition:
    any of them
}