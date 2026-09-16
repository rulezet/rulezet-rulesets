rule TTP_XOR_QUAD_CurrentVersionRun_b5c4 {
  strings:
    $key_b5c4 = { e6 ab [2] c2 a5 [2] e9 89 [2] c7 ab [2] d3 b0 [2] dc aa [2] c2 b7 [2] c0 b6 [2] db b0 [2] c7 b7 [2] db 98 }

  condition:
    any of them
}