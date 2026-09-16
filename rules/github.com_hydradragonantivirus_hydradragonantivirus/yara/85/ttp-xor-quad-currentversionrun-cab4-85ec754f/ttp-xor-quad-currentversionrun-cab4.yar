rule TTP_XOR_QUAD_CurrentVersionRun_cab4 {
  strings:
    $key_cab4 = { 99 db [2] bd d5 [2] 96 f9 [2] b8 db [2] ac c0 [2] a3 da [2] bd c7 [2] bf c6 [2] a4 c0 [2] b8 c7 [2] a4 e8 }

  condition:
    any of them
}