rule TTP_XOR_QUAD_CurrentVersionRun_c5b4 {
  strings:
    $key_c5b4 = { 96 db [2] b2 d5 [2] 99 f9 [2] b7 db [2] a3 c0 [2] ac da [2] b2 c7 [2] b0 c6 [2] ab c0 [2] b7 c7 [2] ab e8 }

  condition:
    any of them
}