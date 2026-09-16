rule TTP_XOR_MULT_DOSStub_dbe5 {
  strings:
    $key_dbe5 = { 8f 8d [2] fb 95 [2] bc 97 [2] fb 86 [2] b5 8a [2] b9 80 [2] ae 8b [2] b5 c5 [2] 88 }

  condition:
    any of them
}