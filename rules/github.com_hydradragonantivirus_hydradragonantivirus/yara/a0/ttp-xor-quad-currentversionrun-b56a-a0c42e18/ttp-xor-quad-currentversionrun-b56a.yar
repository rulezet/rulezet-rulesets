rule TTP_XOR_QUAD_CurrentVersionRun_b56a {
  strings:
    $key_b56a = { e6 05 [2] c2 0b [2] e9 27 [2] c7 05 [2] d3 1e [2] dc 04 [2] c2 19 [2] c0 18 [2] db 1e [2] c7 19 [2] db 36 }

  condition:
    any of them
}