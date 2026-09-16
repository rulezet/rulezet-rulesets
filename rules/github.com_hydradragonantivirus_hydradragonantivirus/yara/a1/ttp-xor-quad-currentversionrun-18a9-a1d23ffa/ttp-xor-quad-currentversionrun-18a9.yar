rule TTP_XOR_QUAD_CurrentVersionRun_18a9 {
  strings:
    $key_18a9 = { 4b c6 [2] 6f c8 [2] 44 e4 [2] 6a c6 [2] 7e dd [2] 71 c7 [2] 6f da [2] 6d db [2] 76 dd [2] 6a da [2] 76 f5 }

  condition:
    any of them
}