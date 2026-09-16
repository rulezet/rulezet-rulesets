rule TTP_XOR_QUAD_CurrentVersionRun_c594 {
  strings:
    $key_c594 = { 96 fb [2] b2 f5 [2] 99 d9 [2] b7 fb [2] a3 e0 [2] ac fa [2] b2 e7 [2] b0 e6 [2] ab e0 [2] b7 e7 [2] ab c8 }

  condition:
    any of them
}