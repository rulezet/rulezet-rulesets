rule TTP_XOR_QUAD_CurrentVersionRun_b5da {
  strings:
    $key_b5da = { e6 b5 [2] c2 bb [2] e9 97 [2] c7 b5 [2] d3 ae [2] dc b4 [2] c2 a9 [2] c0 a8 [2] db ae [2] c7 a9 [2] db 86 }

  condition:
    any of them
}