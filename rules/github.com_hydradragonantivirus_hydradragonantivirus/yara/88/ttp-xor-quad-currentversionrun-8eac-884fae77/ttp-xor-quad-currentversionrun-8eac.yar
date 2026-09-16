rule TTP_XOR_QUAD_CurrentVersionRun_8eac {
  strings:
    $key_8eac = { dd c3 [2] f9 cd [2] d2 e1 [2] fc c3 [2] e8 d8 [2] e7 c2 [2] f9 df [2] fb de [2] e0 d8 [2] fc df [2] e0 f0 }

  condition:
    any of them
}