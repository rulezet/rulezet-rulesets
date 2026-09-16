rule TTP_XOR_QUAD_CurrentVersionRun_61a9 {
  strings:
    $key_61a9 = { 32 c6 [2] 16 c8 [2] 3d e4 [2] 13 c6 [2] 07 dd [2] 08 c7 [2] 16 da [2] 14 db [2] 0f dd [2] 13 da [2] 0f f5 }

  condition:
    any of them
}