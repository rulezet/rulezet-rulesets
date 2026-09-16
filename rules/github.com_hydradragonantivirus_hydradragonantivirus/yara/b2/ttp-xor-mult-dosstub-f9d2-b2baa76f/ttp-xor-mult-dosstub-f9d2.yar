rule TTP_XOR_MULT_DOSStub_f9d2 {
  strings:
    $key_f9d2 = { ad ba [2] d9 a2 [2] 9e a0 [2] d9 b1 [2] 97 bd [2] 9b b7 [2] 8c bc [2] 97 f2 [2] aa }

  condition:
    any of them
}