rule TTP_XOR_MULT_DOSStub_db55 {
  strings:
    $key_db55 = { 8f 3d [2] fb 25 [2] bc 27 [2] fb 36 [2] b5 3a [2] b9 30 [2] ae 3b [2] b5 75 [2] 88 }

  condition:
    any of them
}