rule TTP_XOR_MULT_DOSStub_dbe4 {
  strings:
    $key_dbe4 = { 8f 8c [2] fb 94 [2] bc 96 [2] fb 87 [2] b5 8b [2] b9 81 [2] ae 8a [2] b5 c4 [2] 88 }

  condition:
    any of them
}