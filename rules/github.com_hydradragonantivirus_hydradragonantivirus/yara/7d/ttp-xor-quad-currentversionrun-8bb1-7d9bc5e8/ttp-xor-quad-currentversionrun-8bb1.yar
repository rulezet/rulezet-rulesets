rule TTP_XOR_QUAD_CurrentVersionRun_8bb1 {
  strings:
    $key_8bb1 = { d8 de [2] fc d0 [2] d7 fc [2] f9 de [2] ed c5 [2] e2 df [2] fc c2 [2] fe c3 [2] e5 c5 [2] f9 c2 [2] e5 ed }

  condition:
    any of them
}