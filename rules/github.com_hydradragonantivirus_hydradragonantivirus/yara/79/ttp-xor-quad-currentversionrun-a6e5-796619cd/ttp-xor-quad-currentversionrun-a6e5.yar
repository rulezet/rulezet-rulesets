rule TTP_XOR_QUAD_CurrentVersionRun_a6e5 {
  strings:
    $key_a6e5 = { f5 8a [2] d1 84 [2] fa a8 [2] d4 8a [2] c0 91 [2] cf 8b [2] d1 96 [2] d3 97 [2] c8 91 [2] d4 96 [2] c8 b9 }

  condition:
    any of them
}