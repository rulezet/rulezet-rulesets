rule TTP_XOR_QUAD_CurrentVersionRun_aaa9 {
  strings:
    $key_aaa9 = { f9 c6 [2] dd c8 [2] f6 e4 [2] d8 c6 [2] cc dd [2] c3 c7 [2] dd da [2] df db [2] c4 dd [2] d8 da [2] c4 f5 }

  condition:
    any of them
}