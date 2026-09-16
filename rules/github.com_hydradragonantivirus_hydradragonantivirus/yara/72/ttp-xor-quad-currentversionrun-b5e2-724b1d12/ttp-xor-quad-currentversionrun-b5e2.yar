rule TTP_XOR_QUAD_CurrentVersionRun_b5e2 {
  strings:
    $key_b5e2 = { e6 8d [2] c2 83 [2] e9 af [2] c7 8d [2] d3 96 [2] dc 8c [2] c2 91 [2] c0 90 [2] db 96 [2] c7 91 [2] db be }

  condition:
    any of them
}