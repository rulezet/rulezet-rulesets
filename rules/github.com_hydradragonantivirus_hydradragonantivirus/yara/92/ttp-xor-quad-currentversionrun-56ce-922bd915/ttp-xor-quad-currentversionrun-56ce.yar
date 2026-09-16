rule TTP_XOR_QUAD_CurrentVersionRun_56ce {
  strings:
    $key_56ce = { 05 a1 [2] 21 af [2] 0a 83 [2] 24 a1 [2] 30 ba [2] 3f a0 [2] 21 bd [2] 23 bc [2] 38 ba [2] 24 bd [2] 38 92 }

  condition:
    any of them
}