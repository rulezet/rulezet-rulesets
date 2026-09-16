rule TTP_XOR_MULT_DOSStub_db24 {
  strings:
    $key_db24 = { 8f 4c [2] fb 54 [2] bc 56 [2] fb 47 [2] b5 4b [2] b9 41 [2] ae 4a [2] b5 04 [2] 88 }

  condition:
    any of them
}