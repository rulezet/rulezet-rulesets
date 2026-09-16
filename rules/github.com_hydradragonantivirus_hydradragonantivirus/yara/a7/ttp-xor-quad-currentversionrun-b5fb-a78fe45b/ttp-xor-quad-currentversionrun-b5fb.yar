rule TTP_XOR_QUAD_CurrentVersionRun_b5fb {
  strings:
    $key_b5fb = { e6 94 [2] c2 9a [2] e9 b6 [2] c7 94 [2] d3 8f [2] dc 95 [2] c2 88 [2] c0 89 [2] db 8f [2] c7 88 [2] db a7 }

  condition:
    any of them
}