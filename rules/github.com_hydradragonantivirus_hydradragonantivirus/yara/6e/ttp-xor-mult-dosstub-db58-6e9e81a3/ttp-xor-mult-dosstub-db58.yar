rule TTP_XOR_MULT_DOSStub_db58 {
  strings:
    $key_db58 = { 8f 30 [2] fb 28 [2] bc 2a [2] fb 3b [2] b5 37 [2] b9 3d [2] ae 36 [2] b5 78 [2] 88 }

  condition:
    any of them
}