rule TTP_XOR_QUAD_CurrentVersionRun_bddd {
  strings:
    $key_bddd = { ee b2 [2] ca bc [2] e1 90 [2] cf b2 [2] db a9 [2] d4 b3 [2] ca ae [2] c8 af [2] d3 a9 [2] cf ae [2] d3 81 }

  condition:
    any of them
}