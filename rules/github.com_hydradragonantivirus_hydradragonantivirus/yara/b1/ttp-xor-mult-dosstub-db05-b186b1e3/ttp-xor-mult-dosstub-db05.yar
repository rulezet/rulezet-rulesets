rule TTP_XOR_MULT_DOSStub_db05 {
  strings:
    $key_db05 = { 8f 6d [2] fb 75 [2] bc 77 [2] fb 66 [2] b5 6a [2] b9 60 [2] ae 6b [2] b5 25 [2] 88 }

  condition:
    any of them
}