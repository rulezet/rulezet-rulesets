rule TTP_XOR_QUAD_CurrentVersionRun_3cce {
  strings:
    $key_3cce = { 6f a1 [2] 4b af [2] 60 83 [2] 4e a1 [2] 5a ba [2] 55 a0 [2] 4b bd [2] 49 bc [2] 52 ba [2] 4e bd [2] 52 92 }

  condition:
    any of them
}