rule TTP_XOR_QUAD_CurrentVersionRun_e3d3 {
  strings:
    $key_e3d3 = { b0 bc [2] 94 b2 [2] bf 9e [2] 91 bc [2] 85 a7 [2] 8a bd [2] 94 a0 [2] 96 a1 [2] 8d a7 [2] 91 a0 [2] 8d 8f }

  condition:
    any of them
}