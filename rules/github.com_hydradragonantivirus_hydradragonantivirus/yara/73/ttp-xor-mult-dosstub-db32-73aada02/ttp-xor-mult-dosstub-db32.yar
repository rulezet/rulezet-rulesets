rule TTP_XOR_MULT_DOSStub_db32 {
  strings:
    $key_db32 = { 8f 5a [2] fb 42 [2] bc 40 [2] fb 51 [2] b5 5d [2] b9 57 [2] ae 5c [2] b5 12 [2] 88 }

  condition:
    any of them
}