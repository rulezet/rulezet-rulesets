rule TTP_XOR_QUAD_CurrentVersionRun_e8af {
  strings:
    $key_e8af = { bb c0 [2] 9f ce [2] b4 e2 [2] 9a c0 [2] 8e db [2] 81 c1 [2] 9f dc [2] 9d dd [2] 86 db [2] 9a dc [2] 86 f3 }

  condition:
    any of them
}