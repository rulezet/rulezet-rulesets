rule TTP_XOR_QUAD_CurrentVersionRun_c996 {
  strings:
    $key_c996 = { 9a f9 [2] be f7 [2] 95 db [2] bb f9 [2] af e2 [2] a0 f8 [2] be e5 [2] bc e4 [2] a7 e2 [2] bb e5 [2] a7 ca }

  condition:
    any of them
}