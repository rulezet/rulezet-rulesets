rule TTP_XOR_QUAD_CurrentVersionRun_a2a9 {
  strings:
    $key_a2a9 = { f1 c6 [2] d5 c8 [2] fe e4 [2] d0 c6 [2] c4 dd [2] cb c7 [2] d5 da [2] d7 db [2] cc dd [2] d0 da [2] cc f5 }

  condition:
    any of them
}