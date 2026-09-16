rule TTP_XOR_QUAD_CurrentVersionRun_b524 {
  strings:
    $key_b524 = { e6 4b [2] c2 45 [2] e9 69 [2] c7 4b [2] d3 50 [2] dc 4a [2] c2 57 [2] c0 56 [2] db 50 [2] c7 57 [2] db 78 }

  condition:
    any of them
}