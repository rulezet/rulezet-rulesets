rule TTP_XOR_MULT_DOSStub_db75 {
  strings:
    $key_db75 = { 8f 1d [2] fb 05 [2] bc 07 [2] fb 16 [2] b5 1a [2] b9 10 [2] ae 1b [2] b5 55 [2] 88 }

  condition:
    any of them
}