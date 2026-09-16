rule TTP_XOR_QUAD_CurrentVersionRun_b557 {
  strings:
    $key_b557 = { e6 38 [2] c2 36 [2] e9 1a [2] c7 38 [2] d3 23 [2] dc 39 [2] c2 24 [2] c0 25 [2] db 23 [2] c7 24 [2] db 0b }

  condition:
    any of them
}