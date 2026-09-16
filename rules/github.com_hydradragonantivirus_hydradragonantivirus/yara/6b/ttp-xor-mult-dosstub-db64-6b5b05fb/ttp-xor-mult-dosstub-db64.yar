rule TTP_XOR_MULT_DOSStub_db64 {
  strings:
    $key_db64 = { 8f 0c [2] fb 14 [2] bc 16 [2] fb 07 [2] b5 0b [2] b9 01 [2] ae 0a [2] b5 44 [2] 88 }

  condition:
    any of them
}