rule TTP_XOR_MULT_DOSStub_db09 {
  strings:
    $key_db09 = { 8f 61 [2] fb 79 [2] bc 7b [2] fb 6a [2] b5 66 [2] b9 6c [2] ae 67 [2] b5 29 [2] 88 }

  condition:
    any of them
}