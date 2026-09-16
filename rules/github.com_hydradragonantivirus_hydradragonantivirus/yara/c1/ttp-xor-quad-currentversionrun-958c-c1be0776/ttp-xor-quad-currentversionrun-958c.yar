rule TTP_XOR_QUAD_CurrentVersionRun_958c {
  strings:
    $key_958c = { c6 e3 [2] e2 ed [2] c9 c1 [2] e7 e3 [2] f3 f8 [2] fc e2 [2] e2 ff [2] e0 fe [2] fb f8 [2] e7 ff [2] fb d0 }

  condition:
    any of them
}