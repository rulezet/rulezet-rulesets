rule TTP_XOR_QUAD_CurrentVersionRun_cab5 {
  strings:
    $key_cab5 = { 99 da [2] bd d4 [2] 96 f8 [2] b8 da [2] ac c1 [2] a3 db [2] bd c6 [2] bf c7 [2] a4 c1 [2] b8 c6 [2] a4 e9 }

  condition:
    any of them
}