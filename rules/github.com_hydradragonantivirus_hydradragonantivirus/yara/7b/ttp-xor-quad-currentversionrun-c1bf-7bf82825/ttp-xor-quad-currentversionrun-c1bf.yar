rule TTP_XOR_QUAD_CurrentVersionRun_c1bf {
  strings:
    $key_c1bf = { 92 d0 [2] b6 de [2] 9d f2 [2] b3 d0 [2] a7 cb [2] a8 d1 [2] b6 cc [2] b4 cd [2] af cb [2] b3 cc [2] af e3 }

  condition:
    any of them
}