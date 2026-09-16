rule TTP_XOR_MULT_DOSStub_f9d6 {
  strings:
    $key_f9d6 = { ad be [2] d9 a6 [2] 9e a4 [2] d9 b5 [2] 97 b9 [2] 9b b3 [2] 8c b8 [2] 97 f6 [2] aa }

  condition:
    any of them
}