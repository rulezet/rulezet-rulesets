rule TTP_XOR_MULT_DOSStub_bcc1 {
  strings:
    $key_bcc1 = { e8 a9 [2] 9c b1 [2] db b3 [2] 9c a2 [2] d2 ae [2] de a4 [2] c9 af [2] d2 e1 [2] ef }

  condition:
    any of them
}