rule TTP_XOR_QUAD_CurrentVersionRun_b563 {
  strings:
    $key_b563 = { e6 0c [2] c2 02 [2] e9 2e [2] c7 0c [2] d3 17 [2] dc 0d [2] c2 10 [2] c0 11 [2] db 17 [2] c7 10 [2] db 3f }

  condition:
    any of them
}