rule TTP_XOR_MULT_DOSStub_db74 {
  strings:
    $key_db74 = { 8f 1c [2] fb 04 [2] bc 06 [2] fb 17 [2] b5 1b [2] b9 11 [2] ae 1a [2] b5 54 [2] 88 }

  condition:
    any of them
}