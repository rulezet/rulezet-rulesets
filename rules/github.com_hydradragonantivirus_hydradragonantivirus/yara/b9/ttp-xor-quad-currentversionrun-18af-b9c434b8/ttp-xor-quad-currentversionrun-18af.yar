rule TTP_XOR_QUAD_CurrentVersionRun_18af {
  strings:
    $key_18af = { 4b c0 [2] 6f ce [2] 44 e2 [2] 6a c0 [2] 7e db [2] 71 c1 [2] 6f dc [2] 6d dd [2] 76 db [2] 6a dc [2] 76 f3 }

  condition:
    any of them
}