rule TTP_XOR_QUAD_CurrentVersionRun_d6bf {
  strings:
    $key_d6bf = { 85 d0 [2] a1 de [2] 8a f2 [2] a4 d0 [2] b0 cb [2] bf d1 [2] a1 cc [2] a3 cd [2] b8 cb [2] a4 cc [2] b8 e3 }

  condition:
    any of them
}