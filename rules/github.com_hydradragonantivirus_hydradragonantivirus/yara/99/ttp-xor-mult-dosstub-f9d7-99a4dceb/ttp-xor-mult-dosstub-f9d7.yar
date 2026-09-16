rule TTP_XOR_MULT_DOSStub_f9d7 {
  strings:
    $key_f9d7 = { ad bf [2] d9 a7 [2] 9e a5 [2] d9 b4 [2] 97 b8 [2] 9b b2 [2] 8c b9 [2] 97 f7 [2] aa }

  condition:
    any of them
}