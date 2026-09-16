rule TTP_XOR_QUAD_CurrentVersionRun_58de {
  strings:
    $key_58de = { 0b b1 [2] 2f bf [2] 04 93 [2] 2a b1 [2] 3e aa [2] 31 b0 [2] 2f ad [2] 2d ac [2] 36 aa [2] 2a ad [2] 36 82 }

  condition:
    any of them
}