rule TTP_XOR_QUAD_CurrentVersionRun_d593 {
  strings:
    $key_d593 = { 86 fc [2] a2 f2 [2] 89 de [2] a7 fc [2] b3 e7 [2] bc fd [2] a2 e0 [2] a0 e1 [2] bb e7 [2] a7 e0 [2] bb cf }

  condition:
    any of them
}