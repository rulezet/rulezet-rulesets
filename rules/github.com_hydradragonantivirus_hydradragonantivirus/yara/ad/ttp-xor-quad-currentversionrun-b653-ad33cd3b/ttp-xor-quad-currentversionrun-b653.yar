rule TTP_XOR_QUAD_CurrentVersionRun_b653 {
  strings:
    $key_b653 = { e5 3c [2] c1 32 [2] ea 1e [2] c4 3c [2] d0 27 [2] df 3d [2] c1 20 [2] c3 21 [2] d8 27 [2] c4 20 [2] d8 0f }

  condition:
    any of them
}