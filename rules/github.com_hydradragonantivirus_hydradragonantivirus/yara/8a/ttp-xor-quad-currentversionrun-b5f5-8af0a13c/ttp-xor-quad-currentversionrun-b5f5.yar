rule TTP_XOR_QUAD_CurrentVersionRun_b5f5 {
  strings:
    $key_b5f5 = { e6 9a [2] c2 94 [2] e9 b8 [2] c7 9a [2] d3 81 [2] dc 9b [2] c2 86 [2] c0 87 [2] db 81 [2] c7 86 [2] db a9 }

  condition:
    any of them
}