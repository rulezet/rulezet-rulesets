rule TTP_XOR_QUAD_CurrentVersionRun_71a9 {
  strings:
    $key_71a9 = { 22 c6 [2] 06 c8 [2] 2d e4 [2] 03 c6 [2] 17 dd [2] 18 c7 [2] 06 da [2] 04 db [2] 1f dd [2] 03 da [2] 1f f5 }

  condition:
    any of them
}