rule TTP_XOR_QUAD_CurrentVersionRun_b5f8 {
  strings:
    $key_b5f8 = { e6 97 [2] c2 99 [2] e9 b5 [2] c7 97 [2] d3 8c [2] dc 96 [2] c2 8b [2] c0 8a [2] db 8c [2] c7 8b [2] db a4 }

  condition:
    any of them
}