rule TTP_XOR_QUAD_CurrentVersionRun_b52c {
  strings:
    $key_b52c = { e6 43 [2] c2 4d [2] e9 61 [2] c7 43 [2] d3 58 [2] dc 42 [2] c2 5f [2] c0 5e [2] db 58 [2] c7 5f [2] db 70 }

  condition:
    any of them
}