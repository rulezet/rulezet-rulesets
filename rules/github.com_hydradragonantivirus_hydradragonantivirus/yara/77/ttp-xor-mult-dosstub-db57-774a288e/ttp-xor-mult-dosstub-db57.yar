rule TTP_XOR_MULT_DOSStub_db57 {
  strings:
    $key_db57 = { 8f 3f [2] fb 27 [2] bc 25 [2] fb 34 [2] b5 38 [2] b9 32 [2] ae 39 [2] b5 77 [2] 88 }

  condition:
    any of them
}