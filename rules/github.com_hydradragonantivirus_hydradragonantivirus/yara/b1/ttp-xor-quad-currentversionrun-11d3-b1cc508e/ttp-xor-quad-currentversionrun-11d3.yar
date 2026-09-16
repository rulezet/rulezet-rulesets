rule TTP_XOR_QUAD_CurrentVersionRun_11d3 {
  strings:
    $key_11d3 = { 42 bc [2] 66 b2 [2] 4d 9e [2] 63 bc [2] 77 a7 [2] 78 bd [2] 66 a0 [2] 64 a1 [2] 7f a7 [2] 63 a0 [2] 7f 8f }

  condition:
    any of them
}