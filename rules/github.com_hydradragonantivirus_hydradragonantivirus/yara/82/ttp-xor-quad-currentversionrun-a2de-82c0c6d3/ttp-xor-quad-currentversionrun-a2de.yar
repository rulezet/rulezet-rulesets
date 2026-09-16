rule TTP_XOR_QUAD_CurrentVersionRun_a2de {
  strings:
    $key_a2de = { f1 b1 [2] d5 bf [2] fe 93 [2] d0 b1 [2] c4 aa [2] cb b0 [2] d5 ad [2] d7 ac [2] cc aa [2] d0 ad [2] cc 82 }

  condition:
    any of them
}