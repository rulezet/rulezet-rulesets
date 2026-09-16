rule TTP_XOR_MULT_DOSStub_e9d6 {
  strings:
    $key_e9d6 = { bd be [2] c9 a6 [2] 8e a4 [2] c9 b5 [2] 87 b9 [2] 8b b3 [2] 9c b8 [2] 87 f6 [2] ba }

  condition:
    any of them
}