rule TTP_XOR_QUAD_CurrentVersionRun_bea9 {
  strings:
    $key_bea9 = { ed c6 [2] c9 c8 [2] e2 e4 [2] cc c6 [2] d8 dd [2] d7 c7 [2] c9 da [2] cb db [2] d0 dd [2] cc da [2] d0 f5 }

  condition:
    any of them
}