rule TTP_XOR_QUAD_CurrentVersionRun_a0de {
  strings:
    $key_a0de = { f3 b1 [2] d7 bf [2] fc 93 [2] d2 b1 [2] c6 aa [2] c9 b0 [2] d7 ad [2] d5 ac [2] ce aa [2] d2 ad [2] ce 82 }

  condition:
    any of them
}