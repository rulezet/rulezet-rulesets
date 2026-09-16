rule TTP_XOR_QUAD_CurrentVersionRun_bdde {
  strings:
    $key_bdde = { ee b1 [2] ca bf [2] e1 93 [2] cf b1 [2] db aa [2] d4 b0 [2] ca ad [2] c8 ac [2] d3 aa [2] cf ad [2] d3 82 }

  condition:
    any of them
}