rule TTP_XOR_QUAD_CurrentVersionRun_daba {
  strings:
    $key_daba = { 89 d5 [2] ad db [2] 86 f7 [2] a8 d5 [2] bc ce [2] b3 d4 [2] ad c9 [2] af c8 [2] b4 ce [2] a8 c9 [2] b4 e6 }

  condition:
    any of them
}