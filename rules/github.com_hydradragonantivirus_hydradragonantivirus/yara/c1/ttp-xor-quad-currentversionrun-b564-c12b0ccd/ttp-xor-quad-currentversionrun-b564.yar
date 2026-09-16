rule TTP_XOR_QUAD_CurrentVersionRun_b564 {
  strings:
    $key_b564 = { e6 0b [2] c2 05 [2] e9 29 [2] c7 0b [2] d3 10 [2] dc 0a [2] c2 17 [2] c0 16 [2] db 10 [2] c7 17 [2] db 38 }

  condition:
    any of them
}