rule TTP_XOR_MULT_DOSStub_db91 {
  strings:
    $key_db91 = { 8f f9 [2] fb e1 [2] bc e3 [2] fb f2 [2] b5 fe [2] b9 f4 [2] ae ff [2] b5 b1 [2] 88 }

  condition:
    any of them
}