rule TTP_XOR_QUAD_CurrentVersionRun_b5c7 {
  strings:
    $key_b5c7 = { e6 a8 [2] c2 a6 [2] e9 8a [2] c7 a8 [2] d3 b3 [2] dc a9 [2] c2 b4 [2] c0 b5 [2] db b3 [2] c7 b4 [2] db 9b }

  condition:
    any of them
}