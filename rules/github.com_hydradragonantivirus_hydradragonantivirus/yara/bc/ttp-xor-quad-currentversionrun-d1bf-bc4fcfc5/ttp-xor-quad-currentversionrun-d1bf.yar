rule TTP_XOR_QUAD_CurrentVersionRun_d1bf {
  strings:
    $key_d1bf = { 82 d0 [2] a6 de [2] 8d f2 [2] a3 d0 [2] b7 cb [2] b8 d1 [2] a6 cc [2] a4 cd [2] bf cb [2] a3 cc [2] bf e3 }

  condition:
    any of them
}