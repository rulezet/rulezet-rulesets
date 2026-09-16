rule TTP_XOR_MULT_DOSStub_db86 {
  strings:
    $key_db86 = { 8f ee [2] fb f6 [2] bc f4 [2] fb e5 [2] b5 e9 [2] b9 e3 [2] ae e8 [2] b5 a6 [2] 88 }

  condition:
    any of them
}