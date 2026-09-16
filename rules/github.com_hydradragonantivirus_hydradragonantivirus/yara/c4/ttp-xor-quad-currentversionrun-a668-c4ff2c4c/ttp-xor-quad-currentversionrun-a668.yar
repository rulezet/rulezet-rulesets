rule TTP_XOR_QUAD_CurrentVersionRun_a668 {
  strings:
    $key_a668 = { f5 07 [2] d1 09 [2] fa 25 [2] d4 07 [2] c0 1c [2] cf 06 [2] d1 1b [2] d3 1a [2] c8 1c [2] d4 1b [2] c8 34 }

  condition:
    any of them
}