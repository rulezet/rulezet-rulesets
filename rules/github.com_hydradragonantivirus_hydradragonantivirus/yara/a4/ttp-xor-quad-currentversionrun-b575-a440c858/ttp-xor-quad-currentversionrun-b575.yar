rule TTP_XOR_QUAD_CurrentVersionRun_b575 {
  strings:
    $key_b575 = { e6 1a [2] c2 14 [2] e9 38 [2] c7 1a [2] d3 01 [2] dc 1b [2] c2 06 [2] c0 07 [2] db 01 [2] c7 06 [2] db 29 }

  condition:
    any of them
}