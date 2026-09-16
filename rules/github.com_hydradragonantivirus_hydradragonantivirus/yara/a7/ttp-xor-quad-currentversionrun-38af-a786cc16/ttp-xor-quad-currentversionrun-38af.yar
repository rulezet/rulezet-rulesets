rule TTP_XOR_QUAD_CurrentVersionRun_38af {
  strings:
    $key_38af = { 6b c0 [2] 4f ce [2] 64 e2 [2] 4a c0 [2] 5e db [2] 51 c1 [2] 4f dc [2] 4d dd [2] 56 db [2] 4a dc [2] 56 f3 }

  condition:
    any of them
}