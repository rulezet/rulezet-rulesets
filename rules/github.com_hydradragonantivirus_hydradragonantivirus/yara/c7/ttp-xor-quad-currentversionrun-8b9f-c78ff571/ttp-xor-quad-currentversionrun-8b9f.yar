rule TTP_XOR_QUAD_CurrentVersionRun_8b9f {
  strings:
    $key_8b9f = { d8 f0 [2] fc fe [2] d7 d2 [2] f9 f0 [2] ed eb [2] e2 f1 [2] fc ec [2] fe ed [2] e5 eb [2] f9 ec [2] e5 c3 }

  condition:
    any of them
}