rule TTP_XOR_QUAD_CurrentVersionRun_aa93 {
  strings:
    $key_aa93 = { f9 fc [2] dd f2 [2] f6 de [2] d8 fc [2] cc e7 [2] c3 fd [2] dd e0 [2] df e1 [2] c4 e7 [2] d8 e0 [2] c4 cf }

  condition:
    any of them
}