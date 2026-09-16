rule TTP_XOR_MULT_DOSStub_db27 {
  strings:
    $key_db27 = { 8f 4f [2] fb 57 [2] bc 55 [2] fb 44 [2] b5 48 [2] b9 42 [2] ae 49 [2] b5 07 [2] 88 }

  condition:
    any of them
}