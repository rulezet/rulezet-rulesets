rule TTP_XOR_QUAD_CurrentVersionRun_c98b {
  strings:
    $key_c98b = { 9a e4 [2] be ea [2] 95 c6 [2] bb e4 [2] af ff [2] a0 e5 [2] be f8 [2] bc f9 [2] a7 ff [2] bb f8 [2] a7 d7 }

  condition:
    any of them
}