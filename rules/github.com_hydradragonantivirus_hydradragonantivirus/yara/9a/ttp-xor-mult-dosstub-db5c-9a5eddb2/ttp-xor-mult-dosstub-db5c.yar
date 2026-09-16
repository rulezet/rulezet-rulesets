rule TTP_XOR_MULT_DOSStub_db5c {
  strings:
    $key_db5c = { 8f 34 [2] fb 2c [2] bc 2e [2] fb 3f [2] b5 33 [2] b9 39 [2] ae 32 [2] b5 7c [2] 88 }

  condition:
    any of them
}