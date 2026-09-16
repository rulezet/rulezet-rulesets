rule TTP_XOR_MULT_DOSStub_db47 {
  strings:
    $key_db47 = { 8f 2f [2] fb 37 [2] bc 35 [2] fb 24 [2] b5 28 [2] b9 22 [2] ae 29 [2] b5 67 [2] 88 }

  condition:
    any of them
}