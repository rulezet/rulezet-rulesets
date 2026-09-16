rule TTP_XOR_QUAD_CurrentVersionRun_83ad {
  strings:
    $key_83ad = { d0 c2 [2] f4 cc [2] df e0 [2] f1 c2 [2] e5 d9 [2] ea c3 [2] f4 de [2] f6 df [2] ed d9 [2] f1 de [2] ed f1 }

  condition:
    any of them
}