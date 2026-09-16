rule TTP_XOR_QUAD_CurrentVersionRun_a6c4 {
  strings:
    $key_a6c4 = { f5 ab [2] d1 a5 [2] fa 89 [2] d4 ab [2] c0 b0 [2] cf aa [2] d1 b7 [2] d3 b6 [2] c8 b0 [2] d4 b7 [2] c8 98 }

  condition:
    any of them
}