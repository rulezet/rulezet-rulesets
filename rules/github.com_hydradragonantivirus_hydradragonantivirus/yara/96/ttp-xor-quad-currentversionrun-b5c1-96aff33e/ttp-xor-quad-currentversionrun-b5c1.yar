rule TTP_XOR_QUAD_CurrentVersionRun_b5c1 {
  strings:
    $key_b5c1 = { e6 ae [2] c2 a0 [2] e9 8c [2] c7 ae [2] d3 b5 [2] dc af [2] c2 b2 [2] c0 b3 [2] db b5 [2] c7 b2 [2] db 9d }

  condition:
    any of them
}