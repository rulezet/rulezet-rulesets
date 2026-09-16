rule TTP_XOR_MULT_DOSStub_db62 {
  strings:
    $key_db62 = { 8f 0a [2] fb 12 [2] bc 10 [2] fb 01 [2] b5 0d [2] b9 07 [2] ae 0c [2] b5 42 [2] 88 }

  condition:
    any of them
}