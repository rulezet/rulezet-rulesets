rule TTP_XOR_QUAD_CurrentVersionRun_aa95 {
  strings:
    $key_aa95 = { f9 fa [2] dd f4 [2] f6 d8 [2] d8 fa [2] cc e1 [2] c3 fb [2] dd e6 [2] df e7 [2] c4 e1 [2] d8 e6 [2] c4 c9 }

  condition:
    any of them
}