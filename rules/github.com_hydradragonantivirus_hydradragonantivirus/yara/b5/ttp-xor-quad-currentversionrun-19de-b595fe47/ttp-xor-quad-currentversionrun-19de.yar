rule TTP_XOR_QUAD_CurrentVersionRun_19de {
  strings:
    $key_19de = { 4a b1 [2] 6e bf [2] 45 93 [2] 6b b1 [2] 7f aa [2] 70 b0 [2] 6e ad [2] 6c ac [2] 77 aa [2] 6b ad [2] 77 82 }

  condition:
    any of them
}