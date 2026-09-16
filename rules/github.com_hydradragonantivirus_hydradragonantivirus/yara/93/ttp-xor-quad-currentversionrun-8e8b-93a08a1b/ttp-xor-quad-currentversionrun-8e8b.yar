rule TTP_XOR_QUAD_CurrentVersionRun_8e8b {
  strings:
    $key_8e8b = { dd e4 [2] f9 ea [2] d2 c6 [2] fc e4 [2] e8 ff [2] e7 e5 [2] f9 f8 [2] fb f9 [2] e0 ff [2] fc f8 [2] e0 d7 }

  condition:
    any of them
}