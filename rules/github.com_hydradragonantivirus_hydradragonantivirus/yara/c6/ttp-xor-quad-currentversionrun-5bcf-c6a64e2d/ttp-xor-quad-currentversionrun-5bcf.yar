rule TTP_XOR_QUAD_CurrentVersionRun_5bcf {
  strings:
    $key_5bcf = { 08 a0 [2] 2c ae [2] 07 82 [2] 29 a0 [2] 3d bb [2] 32 a1 [2] 2c bc [2] 2e bd [2] 35 bb [2] 29 bc [2] 35 93 }

  condition:
    any of them
}