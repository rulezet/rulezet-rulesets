rule TTP_XOR_MULT_DOSStub_db90 {
  strings:
    $key_db90 = { 8f f8 [2] fb e0 [2] bc e2 [2] fb f3 [2] b5 ff [2] b9 f5 [2] ae fe [2] b5 b0 [2] 88 }

  condition:
    any of them
}