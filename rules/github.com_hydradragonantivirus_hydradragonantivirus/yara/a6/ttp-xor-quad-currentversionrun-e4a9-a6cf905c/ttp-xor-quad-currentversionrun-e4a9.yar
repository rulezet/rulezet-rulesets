rule TTP_XOR_QUAD_CurrentVersionRun_e4a9 {
  strings:
    $key_e4a9 = { b7 c6 [2] 93 c8 [2] b8 e4 [2] 96 c6 [2] 82 dd [2] 8d c7 [2] 93 da [2] 91 db [2] 8a dd [2] 96 da [2] 8a f5 }

  condition:
    any of them
}