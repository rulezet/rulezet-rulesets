rule TTP_XOR_QUAD_CurrentVersionRun_b5d6 {
  strings:
    $key_b5d6 = { e6 b9 [2] c2 b7 [2] e9 9b [2] c7 b9 [2] d3 a2 [2] dc b8 [2] c2 a5 [2] c0 a4 [2] db a2 [2] c7 a5 [2] db 8a }

  condition:
    any of them
}