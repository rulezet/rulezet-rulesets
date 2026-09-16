rule TTP_XOR_QUAD_CurrentVersionRun_d5ba {
  strings:
    $key_d5ba = { 86 d5 [2] a2 db [2] 89 f7 [2] a7 d5 [2] b3 ce [2] bc d4 [2] a2 c9 [2] a0 c8 [2] bb ce [2] a7 c9 [2] bb e6 }

  condition:
    any of them
}