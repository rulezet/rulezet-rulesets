rule TTP_XOR_QUAD_CurrentVersionRun_b54e {
  strings:
    $key_b54e = { e6 21 [2] c2 2f [2] e9 03 [2] c7 21 [2] d3 3a [2] dc 20 [2] c2 3d [2] c0 3c [2] db 3a [2] c7 3d [2] db 12 }

  condition:
    any of them
}