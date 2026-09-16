rule TTP_XOR_QUAD_CurrentVersionRun_7ba9 {
  strings:
    $key_7ba9 = { 28 c6 [2] 0c c8 [2] 27 e4 [2] 09 c6 [2] 1d dd [2] 12 c7 [2] 0c da [2] 0e db [2] 15 dd [2] 09 da [2] 15 f5 }

  condition:
    any of them
}