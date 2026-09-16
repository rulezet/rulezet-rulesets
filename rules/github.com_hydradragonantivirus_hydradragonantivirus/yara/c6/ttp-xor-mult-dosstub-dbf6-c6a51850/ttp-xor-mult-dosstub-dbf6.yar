rule TTP_XOR_MULT_DOSStub_dbf6 {
  strings:
    $key_dbf6 = { 8f 9e [2] fb 86 [2] bc 84 [2] fb 95 [2] b5 99 [2] b9 93 [2] ae 98 [2] b5 d6 [2] 88 }

  condition:
    any of them
}