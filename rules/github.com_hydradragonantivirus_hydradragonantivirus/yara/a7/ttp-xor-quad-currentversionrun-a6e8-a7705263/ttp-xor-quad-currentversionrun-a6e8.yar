rule TTP_XOR_QUAD_CurrentVersionRun_a6e8 {
  strings:
    $key_a6e8 = { f5 87 [2] d1 89 [2] fa a5 [2] d4 87 [2] c0 9c [2] cf 86 [2] d1 9b [2] d3 9a [2] c8 9c [2] d4 9b [2] c8 b4 }

  condition:
    any of them
}