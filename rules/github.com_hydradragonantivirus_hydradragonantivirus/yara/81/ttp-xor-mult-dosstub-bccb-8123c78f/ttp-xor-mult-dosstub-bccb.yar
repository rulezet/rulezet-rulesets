rule TTP_XOR_MULT_DOSStub_bccb {
  strings:
    $key_bccb = { e8 a3 [2] 9c bb [2] db b9 [2] 9c a8 [2] d2 a4 [2] de ae [2] c9 a5 [2] d2 eb [2] ef }

  condition:
    any of them
}