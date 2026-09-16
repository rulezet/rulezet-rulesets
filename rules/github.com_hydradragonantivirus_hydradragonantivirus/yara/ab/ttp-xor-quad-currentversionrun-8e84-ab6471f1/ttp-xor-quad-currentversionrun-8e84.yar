rule TTP_XOR_QUAD_CurrentVersionRun_8e84 {
  strings:
    $key_8e84 = { dd eb [2] f9 e5 [2] d2 c9 [2] fc eb [2] e8 f0 [2] e7 ea [2] f9 f7 [2] fb f6 [2] e0 f0 [2] fc f7 [2] e0 d8 }

  condition:
    any of them
}