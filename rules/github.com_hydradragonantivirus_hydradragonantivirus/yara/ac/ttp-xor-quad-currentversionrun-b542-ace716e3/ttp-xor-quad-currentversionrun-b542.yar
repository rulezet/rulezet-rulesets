rule TTP_XOR_QUAD_CurrentVersionRun_b542 {
  strings:
    $key_b542 = { e6 2d [2] c2 23 [2] e9 0f [2] c7 2d [2] d3 36 [2] dc 2c [2] c2 31 [2] c0 30 [2] db 36 [2] c7 31 [2] db 1e }

  condition:
    any of them
}