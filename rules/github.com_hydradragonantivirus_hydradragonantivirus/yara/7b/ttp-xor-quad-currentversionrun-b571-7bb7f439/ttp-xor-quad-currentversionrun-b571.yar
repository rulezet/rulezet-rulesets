rule TTP_XOR_QUAD_CurrentVersionRun_b571 {
  strings:
    $key_b571 = { e6 1e [2] c2 10 [2] e9 3c [2] c7 1e [2] d3 05 [2] dc 1f [2] c2 02 [2] c0 03 [2] db 05 [2] c7 02 [2] db 2d }

  condition:
    any of them
}