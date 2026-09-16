rule TTP_XOR_QUAD_CurrentVersionRun_b5fd {
  strings:
    $key_b5fd = { e6 92 [2] c2 9c [2] e9 b0 [2] c7 92 [2] d3 89 [2] dc 93 [2] c2 8e [2] c0 8f [2] db 89 [2] c7 8e [2] db a1 }

  condition:
    any of them
}