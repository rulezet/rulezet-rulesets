rule TTP_XOR_QUAD_CurrentVersionRun_b517 {
  strings:
    $key_b517 = { e6 78 [2] c2 76 [2] e9 5a [2] c7 78 [2] d3 63 [2] dc 79 [2] c2 64 [2] c0 65 [2] db 63 [2] c7 64 [2] db 4b }

  condition:
    any of them
}