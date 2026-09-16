rule TTP_XOR_QUAD_CurrentVersionRun_2bcf {
  strings:
    $key_2bcf = { 78 a0 [2] 5c ae [2] 77 82 [2] 59 a0 [2] 4d bb [2] 42 a1 [2] 5c bc [2] 5e bd [2] 45 bb [2] 59 bc [2] 45 93 }

  condition:
    any of them
}