rule TTP_XOR_QUAD_CurrentVersionRun_49de {
  strings:
    $key_49de = { 1a b1 [2] 3e bf [2] 15 93 [2] 3b b1 [2] 2f aa [2] 20 b0 [2] 3e ad [2] 3c ac [2] 27 aa [2] 3b ad [2] 27 82 }

  condition:
    any of them
}