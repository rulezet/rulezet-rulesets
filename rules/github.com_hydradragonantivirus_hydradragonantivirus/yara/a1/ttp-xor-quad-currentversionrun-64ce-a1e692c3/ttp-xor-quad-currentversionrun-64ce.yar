rule TTP_XOR_QUAD_CurrentVersionRun_64ce {
  strings:
    $key_64ce = { 37 a1 [2] 13 af [2] 38 83 [2] 16 a1 [2] 02 ba [2] 0d a0 [2] 13 bd [2] 11 bc [2] 0a ba [2] 16 bd [2] 0a 92 }

  condition:
    any of them
}