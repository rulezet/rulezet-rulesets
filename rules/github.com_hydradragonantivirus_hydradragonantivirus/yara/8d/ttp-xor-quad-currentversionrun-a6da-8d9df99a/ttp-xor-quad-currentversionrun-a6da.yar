rule TTP_XOR_QUAD_CurrentVersionRun_a6da {
  strings:
    $key_a6da = { f5 b5 [2] d1 bb [2] fa 97 [2] d4 b5 [2] c0 ae [2] cf b4 [2] d1 a9 [2] d3 a8 [2] c8 ae [2] d4 a9 [2] c8 86 }

  condition:
    any of them
}