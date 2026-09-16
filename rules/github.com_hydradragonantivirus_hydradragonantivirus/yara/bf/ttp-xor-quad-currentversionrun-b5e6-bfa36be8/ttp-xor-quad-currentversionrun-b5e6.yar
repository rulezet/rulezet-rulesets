rule TTP_XOR_QUAD_CurrentVersionRun_b5e6 {
  strings:
    $key_b5e6 = { e6 89 [2] c2 87 [2] e9 ab [2] c7 89 [2] d3 92 [2] dc 88 [2] c2 95 [2] c0 94 [2] db 92 [2] c7 95 [2] db ba }

  condition:
    any of them
}