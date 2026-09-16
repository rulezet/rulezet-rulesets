rule TTP_XOR_QUAD_CurrentVersionRun_cd95 {
  strings:
    $key_cd95 = { 9e fa [2] ba f4 [2] 91 d8 [2] bf fa [2] ab e1 [2] a4 fb [2] ba e6 [2] b8 e7 [2] a3 e1 [2] bf e6 [2] a3 c9 }

  condition:
    any of them
}