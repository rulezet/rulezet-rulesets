rule TTP_XOR_QUAD_CurrentVersionRun_06a9 {
  strings:
    $key_06a9 = { 55 c6 [2] 71 c8 [2] 5a e4 [2] 74 c6 [2] 60 dd [2] 6f c7 [2] 71 da [2] 73 db [2] 68 dd [2] 74 da [2] 68 f5 }

  condition:
    any of them
}