rule TTP_XOR_MULT_DOSStub_db15 {
  strings:
    $key_db15 = { 8f 7d [2] fb 65 [2] bc 67 [2] fb 76 [2] b5 7a [2] b9 70 [2] ae 7b [2] b5 35 [2] 88 }

  condition:
    any of them
}