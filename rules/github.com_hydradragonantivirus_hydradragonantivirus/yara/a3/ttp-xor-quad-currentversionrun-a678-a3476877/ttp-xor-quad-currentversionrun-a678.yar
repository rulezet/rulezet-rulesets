rule TTP_XOR_QUAD_CurrentVersionRun_a678 {
  strings:
    $key_a678 = { f5 17 [2] d1 19 [2] fa 35 [2] d4 17 [2] c0 0c [2] cf 16 [2] d1 0b [2] d3 0a [2] c8 0c [2] d4 0b [2] c8 24 }

  condition:
    any of them
}