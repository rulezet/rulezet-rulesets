rule TTP_XOR_QUAD_CurrentVersionRun_b696 {
  strings:
    $key_b696 = { e5 f9 [2] c1 f7 [2] ea db [2] c4 f9 [2] d0 e2 [2] df f8 [2] c1 e5 [2] c3 e4 [2] d8 e2 [2] c4 e5 [2] d8 ca }

  condition:
    any of them
}