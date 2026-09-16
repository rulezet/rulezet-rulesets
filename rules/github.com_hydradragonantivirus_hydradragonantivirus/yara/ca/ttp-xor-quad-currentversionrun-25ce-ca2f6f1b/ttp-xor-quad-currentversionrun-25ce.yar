rule TTP_XOR_QUAD_CurrentVersionRun_25ce {
  strings:
    $key_25ce = { 76 a1 [2] 52 af [2] 79 83 [2] 57 a1 [2] 43 ba [2] 4c a0 [2] 52 bd [2] 50 bc [2] 4b ba [2] 57 bd [2] 4b 92 }

  condition:
    any of them
}