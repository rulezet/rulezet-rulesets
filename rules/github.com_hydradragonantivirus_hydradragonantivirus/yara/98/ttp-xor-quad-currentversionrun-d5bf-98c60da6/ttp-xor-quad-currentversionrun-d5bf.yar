rule TTP_XOR_QUAD_CurrentVersionRun_d5bf {
  strings:
    $key_d5bf = { 86 d0 [2] a2 de [2] 89 f2 [2] a7 d0 [2] b3 cb [2] bc d1 [2] a2 cc [2] a0 cd [2] bb cb [2] a7 cc [2] bb e3 }

  condition:
    any of them
}