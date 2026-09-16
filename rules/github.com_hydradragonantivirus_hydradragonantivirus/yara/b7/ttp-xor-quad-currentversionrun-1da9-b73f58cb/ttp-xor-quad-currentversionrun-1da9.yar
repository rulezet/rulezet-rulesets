rule TTP_XOR_QUAD_CurrentVersionRun_1da9 {
  strings:
    $key_1da9 = { 4e c6 [2] 6a c8 [2] 41 e4 [2] 6f c6 [2] 7b dd [2] 74 c7 [2] 6a da [2] 68 db [2] 73 dd [2] 6f da [2] 73 f5 }

  condition:
    any of them
}