rule TTP_XOR_QUAD_CurrentVersionRun_968c {
  strings:
    $key_968c = { c5 e3 [2] e1 ed [2] ca c1 [2] e4 e3 [2] f0 f8 [2] ff e2 [2] e1 ff [2] e3 fe [2] f8 f8 [2] e4 ff [2] f8 d0 }

  condition:
    any of them
}