rule TTP_XOR_QUAD_CurrentVersionRun_73ce {
  strings:
    $key_73ce = { 20 a1 [2] 04 af [2] 2f 83 [2] 01 a1 [2] 15 ba [2] 1a a0 [2] 04 bd [2] 06 bc [2] 1d ba [2] 01 bd [2] 1d 92 }

  condition:
    any of them
}