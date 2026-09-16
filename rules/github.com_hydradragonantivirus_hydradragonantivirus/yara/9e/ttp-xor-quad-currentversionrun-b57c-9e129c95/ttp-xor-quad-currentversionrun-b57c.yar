rule TTP_XOR_QUAD_CurrentVersionRun_b57c {
  strings:
    $key_b57c = { e6 13 [2] c2 1d [2] e9 31 [2] c7 13 [2] d3 08 [2] dc 12 [2] c2 0f [2] c0 0e [2] db 08 [2] c7 0f [2] db 20 }

  condition:
    any of them
}