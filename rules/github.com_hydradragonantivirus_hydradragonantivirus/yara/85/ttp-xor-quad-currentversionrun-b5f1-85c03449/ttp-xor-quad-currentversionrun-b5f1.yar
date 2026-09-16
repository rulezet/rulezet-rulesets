rule TTP_XOR_QUAD_CurrentVersionRun_b5f1 {
  strings:
    $key_b5f1 = { e6 9e [2] c2 90 [2] e9 bc [2] c7 9e [2] d3 85 [2] dc 9f [2] c2 82 [2] c0 83 [2] db 85 [2] c7 82 [2] db ad }

  condition:
    any of them
}