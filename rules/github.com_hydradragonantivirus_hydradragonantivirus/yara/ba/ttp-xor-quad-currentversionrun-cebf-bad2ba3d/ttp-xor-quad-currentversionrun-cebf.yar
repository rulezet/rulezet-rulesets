rule TTP_XOR_QUAD_CurrentVersionRun_cebf {
  strings:
    $key_cebf = { 9d d0 [2] b9 de [2] 92 f2 [2] bc d0 [2] a8 cb [2] a7 d1 [2] b9 cc [2] bb cd [2] a0 cb [2] bc cc [2] a0 e3 }

  condition:
    any of them
}