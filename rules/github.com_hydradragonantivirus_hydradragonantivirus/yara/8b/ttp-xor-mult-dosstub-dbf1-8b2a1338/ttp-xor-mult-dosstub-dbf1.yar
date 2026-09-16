rule TTP_XOR_MULT_DOSStub_dbf1 {
  strings:
    $key_dbf1 = { 8f 99 [2] fb 81 [2] bc 83 [2] fb 92 [2] b5 9e [2] b9 94 [2] ae 9f [2] b5 d1 [2] 88 }

  condition:
    any of them
}