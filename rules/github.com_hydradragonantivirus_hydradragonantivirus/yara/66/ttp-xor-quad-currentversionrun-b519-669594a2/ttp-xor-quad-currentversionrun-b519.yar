rule TTP_XOR_QUAD_CurrentVersionRun_b519 {
  strings:
    $key_b519 = { e6 76 [2] c2 78 [2] e9 54 [2] c7 76 [2] d3 6d [2] dc 77 [2] c2 6a [2] c0 6b [2] db 6d [2] c7 6a [2] db 45 }

  condition:
    any of them
}