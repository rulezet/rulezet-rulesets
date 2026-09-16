rule TTP_XOR_QUAD_CurrentVersionRun_51a9 {
  strings:
    $key_51a9 = { 02 c6 [2] 26 c8 [2] 0d e4 [2] 23 c6 [2] 37 dd [2] 38 c7 [2] 26 da [2] 24 db [2] 3f dd [2] 23 da [2] 3f f5 }

  condition:
    any of them
}