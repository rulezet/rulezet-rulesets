rule TTP_XOR_QUAD_CurrentVersionRun_8b8d {
  strings:
    $key_8b8d = { d8 e2 [2] fc ec [2] d7 c0 [2] f9 e2 [2] ed f9 [2] e2 e3 [2] fc fe [2] fe ff [2] e5 f9 [2] f9 fe [2] e5 d1 }

  condition:
    any of them
}