rule TTP_XOR_QUAD_CurrentVersionRun_f7d3 {
  strings:
    $key_f7d3 = { a4 bc [2] 80 b2 [2] ab 9e [2] 85 bc [2] 91 a7 [2] 9e bd [2] 80 a0 [2] 82 a1 [2] 99 a7 [2] 85 a0 [2] 99 8f }

  condition:
    any of them
}