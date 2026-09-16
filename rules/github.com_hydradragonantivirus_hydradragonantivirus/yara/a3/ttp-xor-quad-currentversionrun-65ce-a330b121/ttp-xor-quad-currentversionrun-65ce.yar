rule TTP_XOR_QUAD_CurrentVersionRun_65ce {
  strings:
    $key_65ce = { 36 a1 [2] 12 af [2] 39 83 [2] 17 a1 [2] 03 ba [2] 0c a0 [2] 12 bd [2] 10 bc [2] 0b ba [2] 17 bd [2] 0b 92 }

  condition:
    any of them
}