rule TTP_XOR_QUAD_CurrentVersionRun_f3d3 {
  strings:
    $key_f3d3 = { a0 bc [2] 84 b2 [2] af 9e [2] 81 bc [2] 95 a7 [2] 9a bd [2] 84 a0 [2] 86 a1 [2] 9d a7 [2] 81 a0 [2] 9d 8f }

  condition:
    any of them
}