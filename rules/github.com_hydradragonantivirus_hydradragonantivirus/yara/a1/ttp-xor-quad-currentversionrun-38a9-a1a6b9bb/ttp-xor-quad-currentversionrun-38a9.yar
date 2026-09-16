rule TTP_XOR_QUAD_CurrentVersionRun_38a9 {
  strings:
    $key_38a9 = { 6b c6 [2] 4f c8 [2] 64 e4 [2] 4a c6 [2] 5e dd [2] 51 c7 [2] 4f da [2] 4d db [2] 56 dd [2] 4a da [2] 56 f5 }

  condition:
    any of them
}