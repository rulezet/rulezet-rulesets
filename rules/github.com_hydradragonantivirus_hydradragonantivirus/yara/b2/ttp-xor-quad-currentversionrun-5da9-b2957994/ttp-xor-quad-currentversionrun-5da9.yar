rule TTP_XOR_QUAD_CurrentVersionRun_5da9 {
  strings:
    $key_5da9 = { 0e c6 [2] 2a c8 [2] 01 e4 [2] 2f c6 [2] 3b dd [2] 34 c7 [2] 2a da [2] 28 db [2] 33 dd [2] 2f da [2] 33 f5 }

  condition:
    any of them
}