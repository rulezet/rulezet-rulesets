rule TTP_XOR_QUAD_CurrentVersionRun_b52a {
  strings:
    $key_b52a = { e6 45 [2] c2 4b [2] e9 67 [2] c7 45 [2] d3 5e [2] dc 44 [2] c2 59 [2] c0 58 [2] db 5e [2] c7 59 [2] db 76 }

  condition:
    any of them
}