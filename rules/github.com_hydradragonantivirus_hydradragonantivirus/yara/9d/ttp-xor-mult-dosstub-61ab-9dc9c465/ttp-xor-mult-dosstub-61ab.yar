rule TTP_XOR_MULT_DOSStub_61ab {
  strings:
    $key_61ab = { 35 c3 [2] 41 db [2] 06 d9 [2] 41 c8 [2] 0f c4 [2] 03 ce [2] 14 c5 [2] 0f 8b [2] 32 }

  condition:
    any of them
}