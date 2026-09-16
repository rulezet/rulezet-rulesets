rule TTP_XOR_MULT_DOSStub_db45 {
  strings:
    $key_db45 = { 8f 2d [2] fb 35 [2] bc 37 [2] fb 26 [2] b5 2a [2] b9 20 [2] ae 2b [2] b5 65 [2] 88 }

  condition:
    any of them
}