rule TTP_XOR_QUAD_CurrentVersionRun_af8e {
  strings:
    $key_af8e = { fc e1 [2] d8 ef [2] f3 c3 [2] dd e1 [2] c9 fa [2] c6 e0 [2] d8 fd [2] da fc [2] c1 fa [2] dd fd [2] c1 d2 }

  condition:
    any of them
}