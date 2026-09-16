rule TTP_XOR_MULT_DOSStub_db29 {
  strings:
    $key_db29 = { 8f 41 [2] fb 59 [2] bc 5b [2] fb 4a [2] b5 46 [2] b9 4c [2] ae 47 [2] b5 09 [2] 88 }

  condition:
    any of them
}