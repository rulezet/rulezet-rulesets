rule TTP_XOR_MULT_DOSStub_db1c {
  strings:
    $key_db1c = { 8f 74 [2] fb 6c [2] bc 6e [2] fb 7f [2] b5 73 [2] b9 79 [2] ae 72 [2] b5 3c [2] 88 }

  condition:
    any of them
}