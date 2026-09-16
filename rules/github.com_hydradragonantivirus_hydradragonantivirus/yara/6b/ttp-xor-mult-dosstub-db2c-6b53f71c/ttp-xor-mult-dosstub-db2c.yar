rule TTP_XOR_MULT_DOSStub_db2c {
  strings:
    $key_db2c = { 8f 44 [2] fb 5c [2] bc 5e [2] fb 4f [2] b5 43 [2] b9 49 [2] ae 42 [2] b5 0c [2] 88 }

  condition:
    any of them
}