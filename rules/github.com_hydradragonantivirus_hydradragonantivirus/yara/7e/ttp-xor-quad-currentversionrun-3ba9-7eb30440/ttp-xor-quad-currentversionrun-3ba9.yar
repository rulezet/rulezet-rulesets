rule TTP_XOR_QUAD_CurrentVersionRun_3ba9 {
  strings:
    $key_3ba9 = { 68 c6 [2] 4c c8 [2] 67 e4 [2] 49 c6 [2] 5d dd [2] 52 c7 [2] 4c da [2] 4e db [2] 55 dd [2] 49 da [2] 55 f5 }

  condition:
    any of them
}