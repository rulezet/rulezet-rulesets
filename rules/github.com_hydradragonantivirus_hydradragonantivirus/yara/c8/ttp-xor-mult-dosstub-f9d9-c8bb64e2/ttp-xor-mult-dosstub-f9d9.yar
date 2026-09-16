rule TTP_XOR_MULT_DOSStub_f9d9 {
  strings:
    $key_f9d9 = { ad b1 [2] d9 a9 [2] 9e ab [2] d9 ba [2] 97 b6 [2] 9b bc [2] 8c b7 [2] 97 f9 [2] aa }

  condition:
    any of them
}