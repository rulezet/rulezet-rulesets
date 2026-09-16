rule TTP_XOR_MULT_DOSStub_db82 {
  strings:
    $key_db82 = { 8f ea [2] fb f2 [2] bc f0 [2] fb e1 [2] b5 ed [2] b9 e7 [2] ae ec [2] b5 a2 [2] 88 }

  condition:
    any of them
}