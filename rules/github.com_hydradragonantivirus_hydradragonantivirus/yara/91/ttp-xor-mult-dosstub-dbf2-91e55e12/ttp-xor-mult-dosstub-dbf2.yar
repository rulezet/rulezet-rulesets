rule TTP_XOR_MULT_DOSStub_dbf2 {
  strings:
    $key_dbf2 = { 8f 9a [2] fb 82 [2] bc 80 [2] fb 91 [2] b5 9d [2] b9 97 [2] ae 9c [2] b5 d2 [2] 88 }

  condition:
    any of them
}