rule TTP_XOR_QUAD_CurrentVersionRun_a626 {
  strings:
    $key_a626 = { f5 49 [2] d1 47 [2] fa 6b [2] d4 49 [2] c0 52 [2] cf 48 [2] d1 55 [2] d3 54 [2] c8 52 [2] d4 55 [2] c8 7a }

  condition:
    any of them
}