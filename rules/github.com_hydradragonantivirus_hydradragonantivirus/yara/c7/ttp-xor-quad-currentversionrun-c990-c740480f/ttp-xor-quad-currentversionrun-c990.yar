rule TTP_XOR_QUAD_CurrentVersionRun_c990 {
  strings:
    $key_c990 = { 9a ff [2] be f1 [2] 95 dd [2] bb ff [2] af e4 [2] a0 fe [2] be e3 [2] bc e2 [2] a7 e4 [2] bb e3 [2] a7 cc }

  condition:
    any of them
}