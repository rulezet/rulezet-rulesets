rule TTP_XOR_QUAD_CurrentVersionRun_a6f8 {
  strings:
    $key_a6f8 = { f5 97 [2] d1 99 [2] fa b5 [2] d4 97 [2] c0 8c [2] cf 96 [2] d1 8b [2] d3 8a [2] c8 8c [2] d4 8b [2] c8 a4 }

  condition:
    any of them
}