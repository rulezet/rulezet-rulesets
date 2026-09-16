rule TTP_XOR_MULT_DOSStub_bcc2 {
  strings:
    $key_bcc2 = { e8 aa [2] 9c b2 [2] db b0 [2] 9c a1 [2] d2 ad [2] de a7 [2] c9 ac [2] d2 e2 [2] ef }

  condition:
    any of them
}