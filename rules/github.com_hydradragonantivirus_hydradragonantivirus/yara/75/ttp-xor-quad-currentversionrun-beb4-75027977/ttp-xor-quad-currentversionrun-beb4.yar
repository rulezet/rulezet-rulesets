rule TTP_XOR_QUAD_CurrentVersionRun_beb4 {
  strings:
    $key_beb4 = { ed db [2] c9 d5 [2] e2 f9 [2] cc db [2] d8 c0 [2] d7 da [2] c9 c7 [2] cb c6 [2] d0 c0 [2] cc c7 [2] d0 e8 }

  condition:
    any of them
}