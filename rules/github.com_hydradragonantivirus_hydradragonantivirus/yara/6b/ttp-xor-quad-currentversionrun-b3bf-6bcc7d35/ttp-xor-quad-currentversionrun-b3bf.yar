rule TTP_XOR_QUAD_CurrentVersionRun_b3bf {
  strings:
    $key_b3bf = { e0 d0 [2] c4 de [2] ef f2 [2] c1 d0 [2] d5 cb [2] da d1 [2] c4 cc [2] c6 cd [2] dd cb [2] c1 cc [2] dd e3 }

  condition:
    any of them
}