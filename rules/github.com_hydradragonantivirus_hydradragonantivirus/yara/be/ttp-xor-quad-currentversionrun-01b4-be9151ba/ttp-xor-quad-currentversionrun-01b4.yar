rule TTP_XOR_QUAD_CurrentVersionRun_01b4 {
  strings:
    $key_01b4 = { 52 db [2] 76 d5 [2] 5d f9 [2] 73 db [2] 67 c0 [2] 68 da [2] 76 c7 [2] 74 c6 [2] 6f c0 [2] 73 c7 [2] 6f e8 }

  condition:
    any of them
}