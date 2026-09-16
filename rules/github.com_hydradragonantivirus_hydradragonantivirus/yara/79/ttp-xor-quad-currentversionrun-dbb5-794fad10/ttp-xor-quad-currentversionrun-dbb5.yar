rule TTP_XOR_QUAD_CurrentVersionRun_dbb5 {
  strings:
    $key_dbb5 = { 88 da [2] ac d4 [2] 87 f8 [2] a9 da [2] bd c1 [2] b2 db [2] ac c6 [2] ae c7 [2] b5 c1 [2] a9 c6 [2] b5 e9 }

  condition:
    any of them
}