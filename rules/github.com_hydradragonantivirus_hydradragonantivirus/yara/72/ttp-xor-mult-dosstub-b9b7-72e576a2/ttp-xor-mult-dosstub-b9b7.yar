rule TTP_XOR_MULT_DOSStub_b9b7 {
  strings:
    $key_b9b7 = { ed df [2] 99 c7 [2] de c5 [2] 99 d4 [2] d7 d8 [2] db d2 [2] cc d9 [2] d7 97 [2] ea }

  condition:
    any of them
}