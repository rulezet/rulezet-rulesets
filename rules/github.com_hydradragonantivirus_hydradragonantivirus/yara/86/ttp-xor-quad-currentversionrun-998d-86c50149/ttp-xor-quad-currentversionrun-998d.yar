rule TTP_XOR_QUAD_CurrentVersionRun_998d {
  strings:
    $key_998d = { ca e2 [2] ee ec [2] c5 c0 [2] eb e2 [2] ff f9 [2] f0 e3 [2] ee fe [2] ec ff [2] f7 f9 [2] eb fe [2] f7 d1 }

  condition:
    any of them
}