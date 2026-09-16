rule TTP_XOR_QUAD_CurrentVersionRun_a6dd {
  strings:
    $key_a6dd = { f5 b2 [2] d1 bc [2] fa 90 [2] d4 b2 [2] c0 a9 [2] cf b3 [2] d1 ae [2] d3 af [2] c8 a9 [2] d4 ae [2] c8 81 }

  condition:
    any of them
}