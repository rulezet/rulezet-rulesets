rule TTP_XOR_QUAD_CurrentVersionRun_6fcf {
  strings:
    $key_6fcf = { 3c a0 [2] 18 ae [2] 33 82 [2] 1d a0 [2] 09 bb [2] 06 a1 [2] 18 bc [2] 1a bd [2] 01 bb [2] 1d bc [2] 01 93 }

  condition:
    any of them
}