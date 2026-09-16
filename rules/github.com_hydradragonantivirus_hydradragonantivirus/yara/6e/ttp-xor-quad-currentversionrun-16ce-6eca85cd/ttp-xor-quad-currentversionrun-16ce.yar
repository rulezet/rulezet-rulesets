rule TTP_XOR_QUAD_CurrentVersionRun_16ce {
  strings:
    $key_16ce = { 45 a1 [2] 61 af [2] 4a 83 [2] 64 a1 [2] 70 ba [2] 7f a0 [2] 61 bd [2] 63 bc [2] 78 ba [2] 64 bd [2] 78 92 }

  condition:
    any of them
}