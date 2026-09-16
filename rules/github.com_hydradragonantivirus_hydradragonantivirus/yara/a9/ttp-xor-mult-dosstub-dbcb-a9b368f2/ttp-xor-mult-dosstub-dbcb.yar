rule TTP_XOR_MULT_DOSStub_dbcb {
  strings:
    $key_dbcb = { 8f a3 [2] fb bb [2] bc b9 [2] fb a8 [2] b5 a4 [2] b9 ae [2] ae a5 [2] b5 eb [2] 88 }

  condition:
    any of them
}