rule TTP_XOR_QUAD_CurrentVersionRun_b55b {
  strings:
    $key_b55b = { e6 34 [2] c2 3a [2] e9 16 [2] c7 34 [2] d3 2f [2] dc 35 [2] c2 28 [2] c0 29 [2] db 2f [2] c7 28 [2] db 07 }

  condition:
    any of them
}