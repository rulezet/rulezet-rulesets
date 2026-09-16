rule TTP_XOR_MULT_DOSStub_db83 {
  strings:
    $key_db83 = { 8f eb [2] fb f3 [2] bc f1 [2] fb e0 [2] b5 ec [2] b9 e6 [2] ae ed [2] b5 a3 [2] 88 }

  condition:
    any of them
}