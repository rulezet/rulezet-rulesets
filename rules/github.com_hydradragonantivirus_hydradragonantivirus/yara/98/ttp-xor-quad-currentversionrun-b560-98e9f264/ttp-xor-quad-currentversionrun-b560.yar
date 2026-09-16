rule TTP_XOR_QUAD_CurrentVersionRun_b560 {
  strings:
    $key_b560 = { e6 0f [2] c2 01 [2] e9 2d [2] c7 0f [2] d3 14 [2] dc 0e [2] c2 13 [2] c0 12 [2] db 14 [2] c7 13 [2] db 3c }

  condition:
    any of them
}