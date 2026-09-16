rule TTP_XOR_QUAD_CurrentVersionRun_48a9 {
  strings:
    $key_48a9 = { 1b c6 [2] 3f c8 [2] 14 e4 [2] 3a c6 [2] 2e dd [2] 21 c7 [2] 3f da [2] 3d db [2] 26 dd [2] 3a da [2] 26 f5 }

  condition:
    any of them
}