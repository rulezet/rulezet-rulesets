rule TTP_XOR_QUAD_CurrentVersionRun_45ce {
  strings:
    $key_45ce = { 16 a1 [2] 32 af [2] 19 83 [2] 37 a1 [2] 23 ba [2] 2c a0 [2] 32 bd [2] 30 bc [2] 2b ba [2] 37 bd [2] 2b 92 }

  condition:
    any of them
}