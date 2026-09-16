rule TTP_XOR_QUAD_CurrentVersionRun_53ce {
  strings:
    $key_53ce = { 00 a1 [2] 24 af [2] 0f 83 [2] 21 a1 [2] 35 ba [2] 3a a0 [2] 24 bd [2] 26 bc [2] 3d ba [2] 21 bd [2] 3d 92 }

  condition:
    any of them
}