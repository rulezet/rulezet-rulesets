rule TTP_XOR_MULT_DOSStub_db84 {
  strings:
    $key_db84 = { 8f ec [2] fb f4 [2] bc f6 [2] fb e7 [2] b5 eb [2] b9 e1 [2] ae ea [2] b5 a4 [2] 88 }

  condition:
    any of them
}