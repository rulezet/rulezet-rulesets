rule TTP_XOR_QUAD_CurrentVersionRun_eda9 {
  strings:
    $key_eda9 = { be c6 [2] 9a c8 [2] b1 e4 [2] 9f c6 [2] 8b dd [2] 84 c7 [2] 9a da [2] 98 db [2] 83 dd [2] 9f da [2] 83 f5 }

  condition:
    any of them
}