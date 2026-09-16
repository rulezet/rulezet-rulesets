rule TTP_XOR_QUAD_CurrentVersionRun_ecde {
  strings:
    $key_ecde = { bf b1 [2] 9b bf [2] b0 93 [2] 9e b1 [2] 8a aa [2] 85 b0 [2] 9b ad [2] 99 ac [2] 82 aa [2] 9e ad [2] 82 82 }

  condition:
    any of them
}