rule TTP_XOR_QUAD_CurrentVersionRun_de95 {
  strings:
    $key_de95 = { 8d fa [2] a9 f4 [2] 82 d8 [2] ac fa [2] b8 e1 [2] b7 fb [2] a9 e6 [2] ab e7 [2] b0 e1 [2] ac e6 [2] b0 c9 }

  condition:
    any of them
}