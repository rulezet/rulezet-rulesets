rule TTP_XOR_QUAD_CurrentVersionRun_b2e6 {
  strings:
    $key_b2e6 = { e1 89 [2] c5 87 [2] ee ab [2] c0 89 [2] d4 92 [2] db 88 [2] c5 95 [2] c7 94 [2] dc 92 [2] c0 95 [2] dc ba }

  condition:
    any of them
}