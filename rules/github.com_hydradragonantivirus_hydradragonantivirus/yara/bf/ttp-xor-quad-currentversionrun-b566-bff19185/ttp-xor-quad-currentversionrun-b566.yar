rule TTP_XOR_QUAD_CurrentVersionRun_b566 {
  strings:
    $key_b566 = { e6 09 [2] c2 07 [2] e9 2b [2] c7 09 [2] d3 12 [2] dc 08 [2] c2 15 [2] c0 14 [2] db 12 [2] c7 15 [2] db 3a }

  condition:
    any of them
}