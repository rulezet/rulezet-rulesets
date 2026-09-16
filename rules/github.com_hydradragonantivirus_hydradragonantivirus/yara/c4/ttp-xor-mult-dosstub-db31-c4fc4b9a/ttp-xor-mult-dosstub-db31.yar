rule TTP_XOR_MULT_DOSStub_db31 {
  strings:
    $key_db31 = { 8f 59 [2] fb 41 [2] bc 43 [2] fb 52 [2] b5 5e [2] b9 54 [2] ae 5f [2] b5 11 [2] 88 }

  condition:
    any of them
}