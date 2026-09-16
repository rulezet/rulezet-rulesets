rule TTP_XOR_QUAD_CurrentVersionRun_b2de {
  strings:
    $key_b2de = { e1 b1 [2] c5 bf [2] ee 93 [2] c0 b1 [2] d4 aa [2] db b0 [2] c5 ad [2] c7 ac [2] dc aa [2] c0 ad [2] dc 82 }

  condition:
    any of them
}