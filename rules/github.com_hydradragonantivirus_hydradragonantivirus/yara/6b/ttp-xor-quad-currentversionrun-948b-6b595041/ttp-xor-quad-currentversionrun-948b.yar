rule TTP_XOR_QUAD_CurrentVersionRun_948b {
  strings:
    $key_948b = { c7 e4 [2] e3 ea [2] c8 c6 [2] e6 e4 [2] f2 ff [2] fd e5 [2] e3 f8 [2] e1 f9 [2] fa ff [2] e6 f8 [2] fa d7 }

  condition:
    any of them
}