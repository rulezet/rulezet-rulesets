rule TTP_XOR_QUAD_CurrentVersionRun_a655 {
  strings:
    $key_a655 = { f5 3a [2] d1 34 [2] fa 18 [2] d4 3a [2] c0 21 [2] cf 3b [2] d1 26 [2] d3 27 [2] c8 21 [2] d4 26 [2] c8 09 }

  condition:
    any of them
}