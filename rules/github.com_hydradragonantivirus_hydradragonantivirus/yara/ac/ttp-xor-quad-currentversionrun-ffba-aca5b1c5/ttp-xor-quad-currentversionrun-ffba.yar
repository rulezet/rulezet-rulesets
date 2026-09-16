rule TTP_XOR_QUAD_CurrentVersionRun_ffba {
  strings:
    $key_ffba = { ac d5 [2] 88 db [2] a3 f7 [2] 8d d5 [2] 99 ce [2] 96 d4 [2] 88 c9 [2] 8a c8 [2] 91 ce [2] 8d c9 [2] 91 e6 }

  condition:
    any of them
}