rule TTP_XOR_MULT_DOSStub_dbe3 {
  strings:
    $key_dbe3 = { 8f 8b [2] fb 93 [2] bc 91 [2] fb 80 [2] b5 8c [2] b9 86 [2] ae 8d [2] b5 c3 [2] 88 }

  condition:
    any of them
}