rule TTP_XOR_MULT_DOSStub_dbf5 {
  strings:
    $key_dbf5 = { 8f 9d [2] fb 85 [2] bc 87 [2] fb 96 [2] b5 9a [2] b9 90 [2] ae 9b [2] b5 d5 [2] 88 }

  condition:
    any of them
}