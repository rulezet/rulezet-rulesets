rule TTP_XOR_QUAD_CurrentVersionRun_8bac {
  strings:
    $key_8bac = { d8 c3 [2] fc cd [2] d7 e1 [2] f9 c3 [2] ed d8 [2] e2 c2 [2] fc df [2] fe de [2] e5 d8 [2] f9 df [2] e5 f0 }

  condition:
    any of them
}