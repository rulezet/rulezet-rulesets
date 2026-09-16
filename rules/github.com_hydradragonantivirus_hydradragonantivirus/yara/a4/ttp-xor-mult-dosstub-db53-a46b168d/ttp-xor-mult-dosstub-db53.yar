rule TTP_XOR_MULT_DOSStub_db53 {
  strings:
    $key_db53 = { 8f 3b [2] fb 23 [2] bc 21 [2] fb 30 [2] b5 3c [2] b9 36 [2] ae 3d [2] b5 73 [2] 88 }

  condition:
    any of them
}