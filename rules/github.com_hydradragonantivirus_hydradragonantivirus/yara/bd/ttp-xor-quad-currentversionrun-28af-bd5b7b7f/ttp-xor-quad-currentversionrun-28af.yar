rule TTP_XOR_QUAD_CurrentVersionRun_28af {
  strings:
    $key_28af = { 7b c0 [2] 5f ce [2] 74 e2 [2] 5a c0 [2] 4e db [2] 41 c1 [2] 5f dc [2] 5d dd [2] 46 db [2] 5a dc [2] 46 f3 }

  condition:
    any of them
}