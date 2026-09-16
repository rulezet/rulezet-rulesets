rule TTP_XOR_QUAD_CurrentVersionRun_b548 {
  strings:
    $key_b548 = { e6 27 [2] c2 29 [2] e9 05 [2] c7 27 [2] d3 3c [2] dc 26 [2] c2 3b [2] c0 3a [2] db 3c [2] c7 3b [2] db 14 }

  condition:
    any of them
}