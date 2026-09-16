rule TTP_XOR_MULT_DOSStub_bcc5 {
  strings:
    $key_bcc5 = { e8 ad [2] 9c b5 [2] db b7 [2] 9c a6 [2] d2 aa [2] de a0 [2] c9 ab [2] d2 e5 [2] ef }

  condition:
    any of them
}