rule TTP_XOR_MULT_DOSStub_db60 {
  strings:
    $key_db60 = { 8f 08 [2] fb 10 [2] bc 12 [2] fb 03 [2] b5 0f [2] b9 05 [2] ae 0e [2] b5 40 [2] 88 }

  condition:
    any of them
}