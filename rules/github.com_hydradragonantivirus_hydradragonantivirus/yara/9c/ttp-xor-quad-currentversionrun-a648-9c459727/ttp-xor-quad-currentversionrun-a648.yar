rule TTP_XOR_QUAD_CurrentVersionRun_a648 {
  strings:
    $key_a648 = { f5 27 [2] d1 29 [2] fa 05 [2] d4 27 [2] c0 3c [2] cf 26 [2] d1 3b [2] d3 3a [2] c8 3c [2] d4 3b [2] c8 14 }

  condition:
    any of them
}