rule TTP_XOR_QUAD_CurrentVersionRun_69de {
  strings:
    $key_69de = { 3a b1 [2] 1e bf [2] 35 93 [2] 1b b1 [2] 0f aa [2] 00 b0 [2] 1e ad [2] 1c ac [2] 07 aa [2] 1b ad [2] 07 82 }

  condition:
    any of them
}