rule TTP_XOR_QUAD_CurrentVersionRun_809f {
  strings:
    $key_809f = { d3 f0 [2] f7 fe [2] dc d2 [2] f2 f0 [2] e6 eb [2] e9 f1 [2] f7 ec [2] f5 ed [2] ee eb [2] f2 ec [2] ee c3 }

  condition:
    any of them
}