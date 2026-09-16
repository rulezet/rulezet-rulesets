rule TTP_XOR_QUAD_CurrentVersionRun_f4a9 {
  strings:
    $key_f4a9 = { a7 c6 [2] 83 c8 [2] a8 e4 [2] 86 c6 [2] 92 dd [2] 9d c7 [2] 83 da [2] 81 db [2] 9a dd [2] 86 da [2] 9a f5 }

  condition:
    any of them
}