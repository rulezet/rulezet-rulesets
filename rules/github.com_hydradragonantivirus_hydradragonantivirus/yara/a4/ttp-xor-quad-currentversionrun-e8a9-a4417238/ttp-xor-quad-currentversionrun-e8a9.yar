rule TTP_XOR_QUAD_CurrentVersionRun_e8a9 {
  strings:
    $key_e8a9 = { bb c6 [2] 9f c8 [2] b4 e4 [2] 9a c6 [2] 8e dd [2] 81 c7 [2] 9f da [2] 9d db [2] 86 dd [2] 9a da [2] 86 f5 }

  condition:
    any of them
}