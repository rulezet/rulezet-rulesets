rule TTP_XOR_QUAD_CurrentVersionRun_6bcf {
  strings:
    $key_6bcf = { 38 a0 [2] 1c ae [2] 37 82 [2] 19 a0 [2] 0d bb [2] 02 a1 [2] 1c bc [2] 1e bd [2] 05 bb [2] 19 bc [2] 05 93 }

  condition:
    any of them
}