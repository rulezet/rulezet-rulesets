rule TTP_XOR_QUAD_CurrentVersionRun_8ead {
  strings:
    $key_8ead = { dd c2 [2] f9 cc [2] d2 e0 [2] fc c2 [2] e8 d9 [2] e7 c3 [2] f9 de [2] fb df [2] e0 d9 [2] fc de [2] e0 f1 }

  condition:
    any of them
}