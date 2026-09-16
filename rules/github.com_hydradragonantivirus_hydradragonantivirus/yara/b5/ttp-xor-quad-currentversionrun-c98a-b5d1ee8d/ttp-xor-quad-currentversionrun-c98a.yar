rule TTP_XOR_QUAD_CurrentVersionRun_c98a {
  strings:
    $key_c98a = { 9a e5 [2] be eb [2] 95 c7 [2] bb e5 [2] af fe [2] a0 e4 [2] be f9 [2] bc f8 [2] a7 fe [2] bb f9 [2] a7 d6 }

  condition:
    any of them
}