rule TTP_XOR_QUAD_CurrentVersionRun_7cce {
  strings:
    $key_7cce = { 2f a1 [2] 0b af [2] 20 83 [2] 0e a1 [2] 1a ba [2] 15 a0 [2] 0b bd [2] 09 bc [2] 12 ba [2] 0e bd [2] 12 92 }

  condition:
    any of them
}