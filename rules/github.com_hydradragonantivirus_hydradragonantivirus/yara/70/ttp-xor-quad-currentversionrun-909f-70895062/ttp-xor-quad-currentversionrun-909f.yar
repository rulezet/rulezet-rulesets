rule TTP_XOR_QUAD_CurrentVersionRun_909f {
  strings:
    $key_909f = { c3 f0 [2] e7 fe [2] cc d2 [2] e2 f0 [2] f6 eb [2] f9 f1 [2] e7 ec [2] e5 ed [2] fe eb [2] e2 ec [2] fe c3 }

  condition:
    any of them
}