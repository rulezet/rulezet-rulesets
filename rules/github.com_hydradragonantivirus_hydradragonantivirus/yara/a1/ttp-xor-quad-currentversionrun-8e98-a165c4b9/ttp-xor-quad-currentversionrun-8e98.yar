rule TTP_XOR_QUAD_CurrentVersionRun_8e98 {
  strings:
    $key_8e98 = { dd f7 [2] f9 f9 [2] d2 d5 [2] fc f7 [2] e8 ec [2] e7 f6 [2] f9 eb [2] fb ea [2] e0 ec [2] fc eb [2] e0 c4 }

  condition:
    any of them
}