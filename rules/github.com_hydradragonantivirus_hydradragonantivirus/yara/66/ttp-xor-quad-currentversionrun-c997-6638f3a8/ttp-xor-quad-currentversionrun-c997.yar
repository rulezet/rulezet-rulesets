rule TTP_XOR_QUAD_CurrentVersionRun_c997 {
  strings:
    $key_c997 = { 9a f8 [2] be f6 [2] 95 da [2] bb f8 [2] af e3 [2] a0 f9 [2] be e4 [2] bc e5 [2] a7 e3 [2] bb e4 [2] a7 cb }

  condition:
    any of them
}