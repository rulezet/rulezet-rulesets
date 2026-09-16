rule TTP_XOR_MULT_DOSStub_dbe9 {
  strings:
    $key_dbe9 = { 8f 81 [2] fb 99 [2] bc 9b [2] fb 8a [2] b5 86 [2] b9 8c [2] ae 87 [2] b5 c9 [2] 88 }

  condition:
    any of them
}