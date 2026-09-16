rule TTP_XOR_QUAD_CurrentVersionRun_b537 {
  strings:
    $key_b537 = { e6 58 [2] c2 56 [2] e9 7a [2] c7 58 [2] d3 43 [2] dc 59 [2] c2 44 [2] c0 45 [2] db 43 [2] c7 44 [2] db 6b }

  condition:
    any of them
}