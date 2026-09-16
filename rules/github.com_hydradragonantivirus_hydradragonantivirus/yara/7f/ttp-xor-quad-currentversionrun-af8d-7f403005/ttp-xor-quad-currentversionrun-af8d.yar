rule TTP_XOR_QUAD_CurrentVersionRun_af8d {
  strings:
    $key_af8d = { fc e2 [2] d8 ec [2] f3 c0 [2] dd e2 [2] c9 f9 [2] c6 e3 [2] d8 fe [2] da ff [2] c1 f9 [2] dd fe [2] c1 d1 }

  condition:
    any of them
}