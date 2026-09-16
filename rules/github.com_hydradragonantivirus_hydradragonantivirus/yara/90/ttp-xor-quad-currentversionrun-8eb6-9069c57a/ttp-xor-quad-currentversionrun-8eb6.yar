rule TTP_XOR_QUAD_CurrentVersionRun_8eb6 {
  strings:
    $key_8eb6 = { dd d9 [2] f9 d7 [2] d2 fb [2] fc d9 [2] e8 c2 [2] e7 d8 [2] f9 c5 [2] fb c4 [2] e0 c2 [2] fc c5 [2] e0 ea }

  condition:
    any of them
}