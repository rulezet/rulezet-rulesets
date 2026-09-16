rule TTP_XOR_QUAD_CurrentVersionRun_af8a {
  strings:
    $key_af8a = { fc e5 [2] d8 eb [2] f3 c7 [2] dd e5 [2] c9 fe [2] c6 e4 [2] d8 f9 [2] da f8 [2] c1 fe [2] dd f9 [2] c1 d6 }

  condition:
    any of them
}