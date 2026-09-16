rule TTP_XOR_QUAD_CurrentVersionRun_d8a9 {
  strings:
    $key_d8a9 = { 8b c6 [2] af c8 [2] 84 e4 [2] aa c6 [2] be dd [2] b1 c7 [2] af da [2] ad db [2] b6 dd [2] aa da [2] b6 f5 }

  condition:
    any of them
}