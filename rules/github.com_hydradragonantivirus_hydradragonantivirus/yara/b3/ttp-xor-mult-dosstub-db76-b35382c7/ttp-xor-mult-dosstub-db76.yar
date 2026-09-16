rule TTP_XOR_MULT_DOSStub_db76 {
  strings:
    $key_db76 = { 8f 1e [2] fb 06 [2] bc 04 [2] fb 15 [2] b5 19 [2] b9 13 [2] ae 18 [2] b5 56 [2] 88 }

  condition:
    any of them
}