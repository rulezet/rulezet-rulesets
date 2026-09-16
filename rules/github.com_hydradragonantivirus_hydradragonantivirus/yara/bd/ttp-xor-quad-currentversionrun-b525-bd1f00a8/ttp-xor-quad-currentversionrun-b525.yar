rule TTP_XOR_QUAD_CurrentVersionRun_b525 {
  strings:
    $key_b525 = { e6 4a [2] c2 44 [2] e9 68 [2] c7 4a [2] d3 51 [2] dc 4b [2] c2 56 [2] c0 57 [2] db 51 [2] c7 56 [2] db 79 }

  condition:
    any of them
}