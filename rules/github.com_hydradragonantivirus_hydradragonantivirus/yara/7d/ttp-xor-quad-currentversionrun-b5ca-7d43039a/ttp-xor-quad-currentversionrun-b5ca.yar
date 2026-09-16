rule TTP_XOR_QUAD_CurrentVersionRun_b5ca {
  strings:
    $key_b5ca = { e6 a5 [2] c2 ab [2] e9 87 [2] c7 a5 [2] d3 be [2] dc a4 [2] c2 b9 [2] c0 b8 [2] db be [2] c7 b9 [2] db 96 }

  condition:
    any of them
}