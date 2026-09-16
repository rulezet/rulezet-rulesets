rule TTP_XOR_QUAD_CurrentVersionRun_b503 {
  strings:
    $key_b503 = { e6 6c [2] c2 62 [2] e9 4e [2] c7 6c [2] d3 77 [2] dc 6d [2] c2 70 [2] c0 71 [2] db 77 [2] c7 70 [2] db 5f }

  condition:
    any of them
}