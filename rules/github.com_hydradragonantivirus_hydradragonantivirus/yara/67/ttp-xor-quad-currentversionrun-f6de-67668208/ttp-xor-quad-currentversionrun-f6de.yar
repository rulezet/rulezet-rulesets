rule TTP_XOR_QUAD_CurrentVersionRun_f6de {
  strings:
    $key_f6de = { a5 b1 [2] 81 bf [2] aa 93 [2] 84 b1 [2] 90 aa [2] 9f b0 [2] 81 ad [2] 83 ac [2] 98 aa [2] 84 ad [2] 98 82 }

  condition:
    any of them
}