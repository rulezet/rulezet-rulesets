rule TTP_XOR_QUAD_CurrentVersionRun_08a9 {
  strings:
    $key_08a9 = { 5b c6 [2] 7f c8 [2] 54 e4 [2] 7a c6 [2] 6e dd [2] 61 c7 [2] 7f da [2] 7d db [2] 66 dd [2] 7a da [2] 66 f5 }

  condition:
    any of them
}