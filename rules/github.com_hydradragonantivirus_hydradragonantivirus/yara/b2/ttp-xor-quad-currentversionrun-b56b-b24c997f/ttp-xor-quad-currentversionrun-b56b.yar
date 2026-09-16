rule TTP_XOR_QUAD_CurrentVersionRun_b56b {
  strings:
    $key_b56b = { e6 04 [2] c2 0a [2] e9 26 [2] c7 04 [2] d3 1f [2] dc 05 [2] c2 18 [2] c0 19 [2] db 1f [2] c7 18 [2] db 37 }

  condition:
    any of them
}