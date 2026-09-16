rule TTP_XOR_QUAD_CurrentVersionRun_6ea9 {
  strings:
    $key_6ea9 = { 3d c6 [2] 19 c8 [2] 32 e4 [2] 1c c6 [2] 08 dd [2] 07 c7 [2] 19 da [2] 1b db [2] 00 dd [2] 1c da [2] 00 f5 }

  condition:
    any of them
}