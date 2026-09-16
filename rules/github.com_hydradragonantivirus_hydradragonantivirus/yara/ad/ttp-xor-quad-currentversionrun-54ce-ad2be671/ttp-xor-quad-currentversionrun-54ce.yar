rule TTP_XOR_QUAD_CurrentVersionRun_54ce {
  strings:
    $key_54ce = { 07 a1 [2] 23 af [2] 08 83 [2] 26 a1 [2] 32 ba [2] 3d a0 [2] 23 bd [2] 21 bc [2] 3a ba [2] 26 bd [2] 3a 92 }

  condition:
    any of them
}