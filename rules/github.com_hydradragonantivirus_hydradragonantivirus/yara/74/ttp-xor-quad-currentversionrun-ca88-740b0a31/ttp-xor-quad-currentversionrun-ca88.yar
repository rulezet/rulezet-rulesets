rule TTP_XOR_QUAD_CurrentVersionRun_ca88 {
  strings:
    $key_ca88 = { 99 e7 [2] bd e9 [2] 96 c5 [2] b8 e7 [2] ac fc [2] a3 e6 [2] bd fb [2] bf fa [2] a4 fc [2] b8 fb [2] a4 d4 }

  condition:
    any of them
}