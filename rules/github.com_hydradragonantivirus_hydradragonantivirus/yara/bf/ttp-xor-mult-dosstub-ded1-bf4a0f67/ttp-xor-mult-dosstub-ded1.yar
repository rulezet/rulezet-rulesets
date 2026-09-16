rule TTP_XOR_MULT_DOSStub_ded1 {
  strings:
    $key_ded1 = { 8a b9 [2] fe a1 [2] b9 a3 [2] fe b2 [2] b0 be [2] bc b4 [2] ab bf [2] b0 f1 [2] 8d }

  condition:
    any of them
}