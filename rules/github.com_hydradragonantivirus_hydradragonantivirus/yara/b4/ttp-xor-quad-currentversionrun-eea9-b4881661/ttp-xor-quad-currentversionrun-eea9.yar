rule TTP_XOR_QUAD_CurrentVersionRun_eea9 {
  strings:
    $key_eea9 = { bd c6 [2] 99 c8 [2] b2 e4 [2] 9c c6 [2] 88 dd [2] 87 c7 [2] 99 da [2] 9b db [2] 80 dd [2] 9c da [2] 80 f5 }

  condition:
    any of them
}