rule TTP_XOR_QUAD_CurrentVersionRun_cab6 {
  strings:
    $key_cab6 = { 99 d9 [2] bd d7 [2] 96 fb [2] b8 d9 [2] ac c2 [2] a3 d8 [2] bd c5 [2] bf c4 [2] a4 c2 [2] b8 c5 [2] a4 ea }

  condition:
    any of them
}