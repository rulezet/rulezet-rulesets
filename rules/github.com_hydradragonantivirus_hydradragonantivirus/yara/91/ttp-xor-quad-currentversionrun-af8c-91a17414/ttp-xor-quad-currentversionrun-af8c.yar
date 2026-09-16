rule TTP_XOR_QUAD_CurrentVersionRun_af8c {
  strings:
    $key_af8c = { fc e3 [2] d8 ed [2] f3 c1 [2] dd e3 [2] c9 f8 [2] c6 e2 [2] d8 ff [2] da fe [2] c1 f8 [2] dd ff [2] c1 d0 }

  condition:
    any of them
}