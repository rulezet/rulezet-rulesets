rule TTP_XOR_QUAD_CurrentVersionRun_a617 {
  strings:
    $key_a617 = { f5 78 [2] d1 76 [2] fa 5a [2] d4 78 [2] c0 63 [2] cf 79 [2] d1 64 [2] d3 65 [2] c8 63 [2] d4 64 [2] c8 4b }

  condition:
    any of them
}