rule TTP_XOR_MULT_DOSStub_dbf8 {
  strings:
    $key_dbf8 = { 8f 90 [2] fb 88 [2] bc 8a [2] fb 9b [2] b5 97 [2] b9 9d [2] ae 96 [2] b5 d8 [2] 88 }

  condition:
    any of them
}