rule TTP_XOR_QUAD_CurrentVersionRun_b555 {
  strings:
    $key_b555 = { e6 3a [2] c2 34 [2] e9 18 [2] c7 3a [2] d3 21 [2] dc 3b [2] c2 26 [2] c0 27 [2] db 21 [2] c7 26 [2] db 09 }

  condition:
    any of them
}