rule TTP_XOR_QUAD_CurrentVersionRun_b531 {
  strings:
    $key_b531 = { e6 5e [2] c2 50 [2] e9 7c [2] c7 5e [2] d3 45 [2] dc 5f [2] c2 42 [2] c0 43 [2] db 45 [2] c7 42 [2] db 6d }

  condition:
    any of them
}