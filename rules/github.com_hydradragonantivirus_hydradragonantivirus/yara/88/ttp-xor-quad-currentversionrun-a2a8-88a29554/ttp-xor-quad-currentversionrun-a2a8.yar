rule TTP_XOR_QUAD_CurrentVersionRun_a2a8 {
  strings:
    $key_a2a8 = { f1 c7 [2] d5 c9 [2] fe e5 [2] d0 c7 [2] c4 dc [2] cb c6 [2] d5 db [2] d7 da [2] cc dc [2] d0 db [2] cc f4 }

  condition:
    any of them
}