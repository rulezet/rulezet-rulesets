rule TTP_XOR_QUAD_CurrentVersionRun_0aba {
  strings:
    $key_0aba = { 59 d5 [2] 7d db [2] 56 f7 [2] 78 d5 [2] 6c ce [2] 63 d4 [2] 7d c9 [2] 7f c8 [2] 64 ce [2] 78 c9 [2] 64 e6 }

  condition:
    any of them
}