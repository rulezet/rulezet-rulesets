rule TTP_XOR_QUAD_CurrentVersionRun_a677 {
  strings:
    $key_a677 = { f5 18 [2] d1 16 [2] fa 3a [2] d4 18 [2] c0 03 [2] cf 19 [2] d1 04 [2] d3 05 [2] c8 03 [2] d4 04 [2] c8 2b }

  condition:
    any of them
}