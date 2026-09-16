rule TTP_XOR_QUAD_CurrentVersionRun_c353 {
  strings:
    $key_c353 = { 90 3c [2] b4 32 [2] 9f 1e [2] b1 3c [2] a5 27 [2] aa 3d [2] b4 20 [2] b6 21 [2] ad 27 [2] b1 20 [2] ad 0f }

  condition:
    any of them
}