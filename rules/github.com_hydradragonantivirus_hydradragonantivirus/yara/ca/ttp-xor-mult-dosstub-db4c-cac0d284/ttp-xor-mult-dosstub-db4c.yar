rule TTP_XOR_MULT_DOSStub_db4c {
  strings:
    $key_db4c = { 8f 24 [2] fb 3c [2] bc 3e [2] fb 2f [2] b5 23 [2] b9 29 [2] ae 22 [2] b5 6c [2] 88 }

  condition:
    any of them
}