rule TTP_XOR_QUAD_CurrentVersionRun_b565 {
  strings:
    $key_b565 = { e6 0a [2] c2 04 [2] e9 28 [2] c7 0a [2] d3 11 [2] dc 0b [2] c2 16 [2] c0 17 [2] db 11 [2] c7 16 [2] db 39 }

  condition:
    any of them
}