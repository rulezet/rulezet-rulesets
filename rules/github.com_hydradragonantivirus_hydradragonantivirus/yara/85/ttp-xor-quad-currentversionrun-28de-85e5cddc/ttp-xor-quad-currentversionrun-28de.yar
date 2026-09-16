rule TTP_XOR_QUAD_CurrentVersionRun_28de {
  strings:
    $key_28de = { 7b b1 [2] 5f bf [2] 74 93 [2] 5a b1 [2] 4e aa [2] 41 b0 [2] 5f ad [2] 5d ac [2] 46 aa [2] 5a ad [2] 46 82 }

  condition:
    any of them
}