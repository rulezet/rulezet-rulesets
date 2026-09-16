rule TTP_XOR_QUAD_CurrentVersionRun_b554 {
  strings:
    $key_b554 = { e6 3b [2] c2 35 [2] e9 19 [2] c7 3b [2] d3 20 [2] dc 3a [2] c2 27 [2] c0 26 [2] db 20 [2] c7 27 [2] db 08 }

  condition:
    any of them
}