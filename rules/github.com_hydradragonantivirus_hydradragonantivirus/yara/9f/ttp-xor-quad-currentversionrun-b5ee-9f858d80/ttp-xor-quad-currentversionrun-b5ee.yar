rule TTP_XOR_QUAD_CurrentVersionRun_b5ee {
  strings:
    $key_b5ee = { e6 81 [2] c2 8f [2] e9 a3 [2] c7 81 [2] d3 9a [2] dc 80 [2] c2 9d [2] c0 9c [2] db 9a [2] c7 9d [2] db b2 }

  condition:
    any of them
}