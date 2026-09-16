rule TTP_XOR_MULT_DOSStub_db13 {
  strings:
    $key_db13 = { 8f 7b [2] fb 63 [2] bc 61 [2] fb 70 [2] b5 7c [2] b9 76 [2] ae 7d [2] b5 33 [2] 88 }

  condition:
    any of them
}