rule TTP_XOR_QUAD_CurrentVersionRun_36ce {
  strings:
    $key_36ce = { 65 a1 [2] 41 af [2] 6a 83 [2] 44 a1 [2] 50 ba [2] 5f a0 [2] 41 bd [2] 43 bc [2] 58 ba [2] 44 bd [2] 58 92 }

  condition:
    any of them
}