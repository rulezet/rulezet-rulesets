rule TTP_XOR_MULT_DOSStub_ded0 {
  strings:
    $key_ded0 = { 8a b8 [2] fe a0 [2] b9 a2 [2] fe b3 [2] b0 bf [2] bc b5 [2] ab be [2] b0 f0 [2] 8d }

  condition:
    any of them
}