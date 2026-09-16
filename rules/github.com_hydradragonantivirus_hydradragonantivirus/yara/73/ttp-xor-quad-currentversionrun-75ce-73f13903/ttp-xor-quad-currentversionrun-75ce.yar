rule TTP_XOR_QUAD_CurrentVersionRun_75ce {
  strings:
    $key_75ce = { 26 a1 [2] 02 af [2] 29 83 [2] 07 a1 [2] 13 ba [2] 1c a0 [2] 02 bd [2] 00 bc [2] 1b ba [2] 07 bd [2] 1b 92 }

  condition:
    any of them
}