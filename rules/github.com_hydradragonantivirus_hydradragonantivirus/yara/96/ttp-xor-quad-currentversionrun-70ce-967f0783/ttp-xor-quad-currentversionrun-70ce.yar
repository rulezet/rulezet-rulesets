rule TTP_XOR_QUAD_CurrentVersionRun_70ce {
  strings:
    $key_70ce = { 23 a1 [2] 07 af [2] 2c 83 [2] 02 a1 [2] 16 ba [2] 19 a0 [2] 07 bd [2] 05 bc [2] 1e ba [2] 02 bd [2] 1e 92 }

  condition:
    any of them
}