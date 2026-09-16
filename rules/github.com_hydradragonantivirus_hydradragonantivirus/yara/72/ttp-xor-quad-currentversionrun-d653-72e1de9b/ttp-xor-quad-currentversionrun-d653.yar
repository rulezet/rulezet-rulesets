rule TTP_XOR_QUAD_CurrentVersionRun_d653 {
  strings:
    $key_d653 = { 85 3c [2] a1 32 [2] 8a 1e [2] a4 3c [2] b0 27 [2] bf 3d [2] a1 20 [2] a3 21 [2] b8 27 [2] a4 20 [2] b8 0f }

  condition:
    any of them
}