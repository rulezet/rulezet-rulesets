rule TTP_XOR_MULT_DOSStub_b9c5 {
  strings:
    $key_b9c5 = { ed ad [2] 99 b5 [2] de b7 [2] 99 a6 [2] d7 aa [2] db a0 [2] cc ab [2] d7 e5 [2] ea }

  condition:
    any of them
}