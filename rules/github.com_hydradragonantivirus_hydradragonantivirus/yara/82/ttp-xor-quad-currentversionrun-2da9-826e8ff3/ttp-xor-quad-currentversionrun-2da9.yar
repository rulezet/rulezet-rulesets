rule TTP_XOR_QUAD_CurrentVersionRun_2da9 {
  strings:
    $key_2da9 = { 7e c6 [2] 5a c8 [2] 71 e4 [2] 5f c6 [2] 4b dd [2] 44 c7 [2] 5a da [2] 58 db [2] 43 dd [2] 5f da [2] 43 f5 }

  condition:
    any of them
}