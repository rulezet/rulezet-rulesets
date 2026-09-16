rule TTP_XOR_MULT_DOSStub_bcc9 {
  strings:
    $key_bcc9 = { e8 a1 [2] 9c b9 [2] db bb [2] 9c aa [2] d2 a6 [2] de ac [2] c9 a7 [2] d2 e9 [2] ef }

  condition:
    any of them
}