rule TTP_XOR_QUAD_CurrentVersionRun_bddb {
  strings:
    $key_bddb = { ee b4 [2] ca ba [2] e1 96 [2] cf b4 [2] db af [2] d4 b5 [2] ca a8 [2] c8 a9 [2] d3 af [2] cf a8 [2] d3 87 }

  condition:
    any of them
}