rule TTP_XOR_QUAD_CurrentVersionRun_cc53 {
  strings:
    $key_cc53 = { 9f 3c [2] bb 32 [2] 90 1e [2] be 3c [2] aa 27 [2] a5 3d [2] bb 20 [2] b9 21 [2] a2 27 [2] be 20 [2] a2 0f }

  condition:
    any of them
}