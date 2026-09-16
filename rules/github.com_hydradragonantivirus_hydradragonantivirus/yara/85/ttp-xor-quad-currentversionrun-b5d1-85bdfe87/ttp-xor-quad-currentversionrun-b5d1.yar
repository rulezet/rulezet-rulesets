rule TTP_XOR_QUAD_CurrentVersionRun_b5d1 {
  strings:
    $key_b5d1 = { e6 be [2] c2 b0 [2] e9 9c [2] c7 be [2] d3 a5 [2] dc bf [2] c2 a2 [2] c0 a3 [2] db a5 [2] c7 a2 [2] db 8d }

  condition:
    any of them
}