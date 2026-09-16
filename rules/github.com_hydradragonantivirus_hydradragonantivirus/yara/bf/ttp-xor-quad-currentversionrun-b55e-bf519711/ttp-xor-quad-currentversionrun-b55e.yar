rule TTP_XOR_QUAD_CurrentVersionRun_b55e {
  strings:
    $key_b55e = { e6 31 [2] c2 3f [2] e9 13 [2] c7 31 [2] d3 2a [2] dc 30 [2] c2 2d [2] c0 2c [2] db 2a [2] c7 2d [2] db 02 }

  condition:
    any of them
}