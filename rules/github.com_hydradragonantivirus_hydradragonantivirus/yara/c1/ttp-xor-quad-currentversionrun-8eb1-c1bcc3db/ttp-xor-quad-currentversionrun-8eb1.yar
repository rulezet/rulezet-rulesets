rule TTP_XOR_QUAD_CurrentVersionRun_8eb1 {
  strings:
    $key_8eb1 = { dd de [2] f9 d0 [2] d2 fc [2] fc de [2] e8 c5 [2] e7 df [2] f9 c2 [2] fb c3 [2] e0 c5 [2] fc c2 [2] e0 ed }

  condition:
    any of them
}