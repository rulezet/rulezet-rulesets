rule TTP_XOR_QUAD_CurrentVersionRun_dbba {
  strings:
    $key_dbba = { 88 d5 [2] ac db [2] 87 f7 [2] a9 d5 [2] bd ce [2] b2 d4 [2] ac c9 [2] ae c8 [2] b5 ce [2] a9 c9 [2] b5 e6 }

  condition:
    any of them
}