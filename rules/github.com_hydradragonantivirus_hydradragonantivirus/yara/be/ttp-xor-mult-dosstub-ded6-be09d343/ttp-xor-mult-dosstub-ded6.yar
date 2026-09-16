rule TTP_XOR_MULT_DOSStub_ded6 {
  strings:
    $key_ded6 = { 8a be [2] fe a6 [2] b9 a4 [2] fe b5 [2] b0 b9 [2] bc b3 [2] ab b8 [2] b0 f6 [2] 8d }

  condition:
    any of them
}