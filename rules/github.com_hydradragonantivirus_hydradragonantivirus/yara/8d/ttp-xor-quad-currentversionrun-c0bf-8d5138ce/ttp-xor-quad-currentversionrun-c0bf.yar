rule TTP_XOR_QUAD_CurrentVersionRun_c0bf {
  strings:
    $key_c0bf = { 93 d0 [2] b7 de [2] 9c f2 [2] b2 d0 [2] a6 cb [2] a9 d1 [2] b7 cc [2] b5 cd [2] ae cb [2] b2 cc [2] ae e3 }

  condition:
    any of them
}