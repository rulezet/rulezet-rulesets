rule TTP_XOR_QUAD_CurrentVersionRun_a6e9 {
  strings:
    $key_a6e9 = { f5 86 [2] d1 88 [2] fa a4 [2] d4 86 [2] c0 9d [2] cf 87 [2] d1 9a [2] d3 9b [2] c8 9d [2] d4 9a [2] c8 b5 }

  condition:
    any of them
}