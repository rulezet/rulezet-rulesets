rule TTP_XOR_QUAD_CurrentVersionRun_949f {
  strings:
    $key_949f = { c7 f0 [2] e3 fe [2] c8 d2 [2] e6 f0 [2] f2 eb [2] fd f1 [2] e3 ec [2] e1 ed [2] fa eb [2] e6 ec [2] fa c3 }

  condition:
    any of them
}