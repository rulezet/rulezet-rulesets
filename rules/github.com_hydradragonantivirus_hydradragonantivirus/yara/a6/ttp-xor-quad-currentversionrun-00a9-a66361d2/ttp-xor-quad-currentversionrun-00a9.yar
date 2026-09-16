rule TTP_XOR_QUAD_CurrentVersionRun_00a9 {
  strings:
    $key_00a9 = { 53 c6 [2] 77 c8 [2] 5c e4 [2] 72 c6 [2] 66 dd [2] 69 c7 [2] 77 da [2] 75 db [2] 6e dd [2] 72 da [2] 6e f5 }

  condition:
    any of them
}