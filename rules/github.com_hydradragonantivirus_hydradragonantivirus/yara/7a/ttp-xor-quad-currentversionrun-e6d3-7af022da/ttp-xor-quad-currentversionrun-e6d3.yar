rule TTP_XOR_QUAD_CurrentVersionRun_e6d3 {
  strings:
    $key_e6d3 = { b5 bc [2] 91 b2 [2] ba 9e [2] 94 bc [2] 80 a7 [2] 8f bd [2] 91 a0 [2] 93 a1 [2] 88 a7 [2] 94 a0 [2] 88 8f }

  condition:
    any of them
}