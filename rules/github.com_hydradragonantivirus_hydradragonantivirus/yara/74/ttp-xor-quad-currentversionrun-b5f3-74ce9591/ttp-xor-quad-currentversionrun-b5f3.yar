rule TTP_XOR_QUAD_CurrentVersionRun_b5f3 {
  strings:
    $key_b5f3 = { e6 9c [2] c2 92 [2] e9 be [2] c7 9c [2] d3 87 [2] dc 9d [2] c2 80 [2] c0 81 [2] db 87 [2] c7 80 [2] db af }

  condition:
    any of them
}