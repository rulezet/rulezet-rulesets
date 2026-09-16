rule TTP_XOR_QUAD_CurrentVersionRun_b69a {
  strings:
    $key_b69a = { e5 f5 [2] c1 fb [2] ea d7 [2] c4 f5 [2] d0 ee [2] df f4 [2] c1 e9 [2] c3 e8 [2] d8 ee [2] c4 e9 [2] d8 c6 }

  condition:
    any of them
}