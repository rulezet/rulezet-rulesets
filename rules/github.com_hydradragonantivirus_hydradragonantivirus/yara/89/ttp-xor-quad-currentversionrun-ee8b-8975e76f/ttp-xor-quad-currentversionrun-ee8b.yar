rule TTP_XOR_QUAD_CurrentVersionRun_ee8b {
  strings:
    $key_ee8b = { bd e4 [2] 99 ea [2] b2 c6 [2] 9c e4 [2] 88 ff [2] 87 e5 [2] 99 f8 [2] 9b f9 [2] 80 ff [2] 9c f8 [2] 80 d7 }

  condition:
    any of them
}