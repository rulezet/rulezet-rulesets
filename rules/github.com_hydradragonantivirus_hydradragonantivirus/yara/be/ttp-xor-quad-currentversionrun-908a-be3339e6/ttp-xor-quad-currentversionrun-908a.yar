rule TTP_XOR_QUAD_CurrentVersionRun_908a {
  strings:
    $key_908a = { c3 e5 [2] e7 eb [2] cc c7 [2] e2 e5 [2] f6 fe [2] f9 e4 [2] e7 f9 [2] e5 f8 [2] fe fe [2] e2 f9 [2] fe d6 }

  condition:
    any of them
}