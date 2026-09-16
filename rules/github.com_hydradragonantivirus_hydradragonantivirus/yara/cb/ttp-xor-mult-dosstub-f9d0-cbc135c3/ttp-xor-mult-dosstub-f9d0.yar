rule TTP_XOR_MULT_DOSStub_f9d0 {
  strings:
    $key_f9d0 = { ad b8 [2] d9 a0 [2] 9e a2 [2] d9 b3 [2] 97 bf [2] 9b b5 [2] 8c be [2] 97 f0 [2] aa }

  condition:
    any of them
}