rule TTP_XOR_MULT_DOSStub_de88 {
  strings:
    $key_de88 = { 8a e0 [2] fe f8 [2] b9 fa [2] fe eb [2] b0 e7 [2] bc ed [2] ab e6 [2] b0 a8 [2] 8d }

  condition:
    any of them
}