rule TTP_XOR_QUAD_CurrentVersionRun_a624 {
  strings:
    $key_a624 = { f5 4b [2] d1 45 [2] fa 69 [2] d4 4b [2] c0 50 [2] cf 4a [2] d1 57 [2] d3 56 [2] c8 50 [2] d4 57 [2] c8 78 }

  condition:
    any of them
}