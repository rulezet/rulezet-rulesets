rule TTP_XOR_MULT_DOSStub_db68 {
  strings:
    $key_db68 = { 8f 00 [2] fb 18 [2] bc 1a [2] fb 0b [2] b5 07 [2] b9 0d [2] ae 06 [2] b5 48 [2] 88 }

  condition:
    any of them
}