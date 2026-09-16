rule TTP_XOR_QUAD_CurrentVersionRun_deb5 {
  strings:
    $key_deb5 = { 8d da [2] a9 d4 [2] 82 f8 [2] ac da [2] b8 c1 [2] b7 db [2] a9 c6 [2] ab c7 [2] b0 c1 [2] ac c6 [2] b0 e9 }

  condition:
    any of them
}