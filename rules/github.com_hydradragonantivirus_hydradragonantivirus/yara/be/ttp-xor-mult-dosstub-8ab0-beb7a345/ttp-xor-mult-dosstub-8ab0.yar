rule TTP_XOR_MULT_DOSStub_8ab0 {
  strings:
    $key_8ab0 = { de d8 [2] aa c0 [2] ed c2 [2] aa d3 [2] e4 df [2] e8 d5 [2] ff de [2] e4 90 [2] d9 }

  condition:
    any of them
}