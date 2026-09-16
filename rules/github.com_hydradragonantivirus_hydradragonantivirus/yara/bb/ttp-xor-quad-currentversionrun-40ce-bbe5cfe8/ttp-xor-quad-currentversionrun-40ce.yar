rule TTP_XOR_QUAD_CurrentVersionRun_40ce {
  strings:
    $key_40ce = { 13 a1 [2] 37 af [2] 1c 83 [2] 32 a1 [2] 26 ba [2] 29 a0 [2] 37 bd [2] 35 bc [2] 2e ba [2] 32 bd [2] 2e 92 }

  condition:
    any of them
}