rule TTP_XOR_QUAD_CurrentVersionRun_bcde {
  strings:
    $key_bcde = { ef b1 [2] cb bf [2] e0 93 [2] ce b1 [2] da aa [2] d5 b0 [2] cb ad [2] c9 ac [2] d2 aa [2] ce ad [2] d2 82 }

  condition:
    any of them
}