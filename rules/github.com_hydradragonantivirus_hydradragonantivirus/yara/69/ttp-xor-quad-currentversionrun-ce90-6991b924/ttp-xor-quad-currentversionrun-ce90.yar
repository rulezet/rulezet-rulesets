rule TTP_XOR_QUAD_CurrentVersionRun_ce90 {
  strings:
    $key_ce90 = { 9d ff [2] b9 f1 [2] 92 dd [2] bc ff [2] a8 e4 [2] a7 fe [2] b9 e3 [2] bb e2 [2] a0 e4 [2] bc e3 [2] a0 cc }

  condition:
    any of them
}