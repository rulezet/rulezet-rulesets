rule TTP_XOR_QUAD_CurrentVersionRun_eba9 {
  strings:
    $key_eba9 = { b8 c6 [2] 9c c8 [2] b7 e4 [2] 99 c6 [2] 8d dd [2] 82 c7 [2] 9c da [2] 9e db [2] 85 dd [2] 99 da [2] 85 f5 }

  condition:
    any of them
}