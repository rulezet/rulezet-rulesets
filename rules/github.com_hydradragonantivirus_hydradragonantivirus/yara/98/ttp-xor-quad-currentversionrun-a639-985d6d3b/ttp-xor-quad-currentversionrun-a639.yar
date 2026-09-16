rule TTP_XOR_QUAD_CurrentVersionRun_a639 {
  strings:
    $key_a639 = { f5 56 [2] d1 58 [2] fa 74 [2] d4 56 [2] c0 4d [2] cf 57 [2] d1 4a [2] d3 4b [2] c8 4d [2] d4 4a [2] c8 65 }

  condition:
    any of them
}