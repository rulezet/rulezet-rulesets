rule TTP_XOR_MULT_DOSStub_8ab7 {
  strings:
    $key_8ab7 = { de df [2] aa c7 [2] ed c5 [2] aa d4 [2] e4 d8 [2] e8 d2 [2] ff d9 [2] e4 97 [2] d9 }

  condition:
    any of them
}