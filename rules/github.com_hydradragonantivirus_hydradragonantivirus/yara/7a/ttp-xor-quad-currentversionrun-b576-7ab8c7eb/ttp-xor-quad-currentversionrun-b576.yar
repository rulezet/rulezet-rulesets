rule TTP_XOR_QUAD_CurrentVersionRun_b576 {
  strings:
    $key_b576 = { e6 19 [2] c2 17 [2] e9 3b [2] c7 19 [2] d3 02 [2] dc 18 [2] c2 05 [2] c0 04 [2] db 02 [2] c7 05 [2] db 2a }

  condition:
    any of them
}