rule TTP_XOR_QUAD_CurrentVersionRun_b5fa {
  strings:
    $key_b5fa = { e6 95 [2] c2 9b [2] e9 b7 [2] c7 95 [2] d3 8e [2] dc 94 [2] c2 89 [2] c0 88 [2] db 8e [2] c7 89 [2] db a6 }

  condition:
    any of them
}