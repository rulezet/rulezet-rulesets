rule TTP_XOR_QUAD_CurrentVersionRun_e0de {
  strings:
    $key_e0de = { b3 b1 [2] 97 bf [2] bc 93 [2] 92 b1 [2] 86 aa [2] 89 b0 [2] 97 ad [2] 95 ac [2] 8e aa [2] 92 ad [2] 8e 82 }

  condition:
    any of them
}