rule TTP_XOR_QUAD_CurrentVersionRun_cfa9 {
  strings:
    $key_cfa9 = { 9c c6 [2] b8 c8 [2] 93 e4 [2] bd c6 [2] a9 dd [2] a6 c7 [2] b8 da [2] ba db [2] a1 dd [2] bd da [2] a1 f5 }

  condition:
    any of them
}