rule TTP_XOR_MULT_DOSStub_db69 {
  strings:
    $key_db69 = { 8f 01 [2] fb 19 [2] bc 1b [2] fb 0a [2] b5 06 [2] b9 0c [2] ae 07 [2] b5 49 [2] 88 }

  condition:
    any of them
}