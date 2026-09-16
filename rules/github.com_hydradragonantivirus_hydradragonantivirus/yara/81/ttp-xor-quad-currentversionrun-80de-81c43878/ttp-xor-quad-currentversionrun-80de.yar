rule TTP_XOR_QUAD_CurrentVersionRun_80de {
  strings:
    $key_80de = { d3 b1 [2] f7 bf [2] dc 93 [2] f2 b1 [2] e6 aa [2] e9 b0 [2] f7 ad [2] f5 ac [2] ee aa [2] f2 ad [2] ee 82 }

  condition:
    any of them
}