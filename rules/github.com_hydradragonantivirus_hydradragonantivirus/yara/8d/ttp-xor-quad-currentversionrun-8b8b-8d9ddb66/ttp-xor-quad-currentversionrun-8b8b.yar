rule TTP_XOR_QUAD_CurrentVersionRun_8b8b {
  strings:
    $key_8b8b = { d8 e4 [2] fc ea [2] d7 c6 [2] f9 e4 [2] ed ff [2] e2 e5 [2] fc f8 [2] fe f9 [2] e5 ff [2] f9 f8 [2] e5 d7 }

  condition:
    any of them
}