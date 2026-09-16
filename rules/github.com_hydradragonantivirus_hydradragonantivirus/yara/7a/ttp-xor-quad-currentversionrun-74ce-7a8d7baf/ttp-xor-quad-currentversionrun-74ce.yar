rule TTP_XOR_QUAD_CurrentVersionRun_74ce {
  strings:
    $key_74ce = { 27 a1 [2] 03 af [2] 28 83 [2] 06 a1 [2] 12 ba [2] 1d a0 [2] 03 bd [2] 01 bc [2] 1a ba [2] 06 bd [2] 1a 92 }

  condition:
    any of them
}