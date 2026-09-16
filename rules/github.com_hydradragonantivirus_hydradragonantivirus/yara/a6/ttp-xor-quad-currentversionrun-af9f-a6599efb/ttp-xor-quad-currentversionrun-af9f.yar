rule TTP_XOR_QUAD_CurrentVersionRun_af9f {
  strings:
    $key_af9f = { fc f0 [2] d8 fe [2] f3 d2 [2] dd f0 [2] c9 eb [2] c6 f1 [2] d8 ec [2] da ed [2] c1 eb [2] dd ec [2] c1 c3 }

  condition:
    any of them
}