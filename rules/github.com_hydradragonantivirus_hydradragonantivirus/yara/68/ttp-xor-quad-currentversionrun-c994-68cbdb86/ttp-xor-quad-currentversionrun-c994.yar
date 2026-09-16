rule TTP_XOR_QUAD_CurrentVersionRun_c994 {
  strings:
    $key_c994 = { 9a fb [2] be f5 [2] 95 d9 [2] bb fb [2] af e0 [2] a0 fa [2] be e7 [2] bc e6 [2] a7 e0 [2] bb e7 [2] a7 c8 }

  condition:
    any of them
}