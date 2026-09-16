rule TTP_XOR_MULT_DOSStub_db5b {
  strings:
    $key_db5b = { 8f 33 [2] fb 2b [2] bc 29 [2] fb 38 [2] b5 34 [2] b9 3e [2] ae 35 [2] b5 7b [2] 88 }

  condition:
    any of them
}