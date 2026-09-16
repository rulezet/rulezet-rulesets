rule TTP_XOR_QUAD_CurrentVersionRun_aa87 {
  strings:
    $key_aa87 = { f9 e8 [2] dd e6 [2] f6 ca [2] d8 e8 [2] cc f3 [2] c3 e9 [2] dd f4 [2] df f5 [2] c4 f3 [2] d8 f4 [2] c4 db }

  condition:
    any of them
}