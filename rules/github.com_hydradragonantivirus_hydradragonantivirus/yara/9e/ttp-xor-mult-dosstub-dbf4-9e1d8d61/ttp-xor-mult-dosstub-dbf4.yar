rule TTP_XOR_MULT_DOSStub_dbf4 {
  strings:
    $key_dbf4 = { 8f 9c [2] fb 84 [2] bc 86 [2] fb 97 [2] b5 9b [2] b9 91 [2] ae 9a [2] b5 d4 [2] 88 }

  condition:
    any of them
}