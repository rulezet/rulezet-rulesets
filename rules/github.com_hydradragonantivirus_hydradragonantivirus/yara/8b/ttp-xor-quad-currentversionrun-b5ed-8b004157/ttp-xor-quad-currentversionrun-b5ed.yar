rule TTP_XOR_QUAD_CurrentVersionRun_b5ed {
  strings:
    $key_b5ed = { e6 82 [2] c2 8c [2] e9 a0 [2] c7 82 [2] d3 99 [2] dc 83 [2] c2 9e [2] c0 9f [2] db 99 [2] c7 9e [2] db b1 }

  condition:
    any of them
}