rule TTP_XOR_QUAD_CurrentVersionRun_8b8a {
  strings:
    $key_8b8a = { d8 e5 [2] fc eb [2] d7 c7 [2] f9 e5 [2] ed fe [2] e2 e4 [2] fc f9 [2] fe f8 [2] e5 fe [2] f9 f9 [2] e5 d6 }

  condition:
    any of them
}