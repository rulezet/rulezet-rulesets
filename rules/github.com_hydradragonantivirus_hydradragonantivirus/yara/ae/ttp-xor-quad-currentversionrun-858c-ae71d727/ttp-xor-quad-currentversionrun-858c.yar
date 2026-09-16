rule TTP_XOR_QUAD_CurrentVersionRun_858c {
  strings:
    $key_858c = { d6 e3 [2] f2 ed [2] d9 c1 [2] f7 e3 [2] e3 f8 [2] ec e2 [2] f2 ff [2] f0 fe [2] eb f8 [2] f7 ff [2] eb d0 }

  condition:
    any of them
}