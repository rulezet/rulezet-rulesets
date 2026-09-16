rule TTP_XOR_MULT_DOSStub_f986 {
  strings:
    $key_f986 = { ad ee [2] d9 f6 [2] 9e f4 [2] d9 e5 [2] 97 e9 [2] 9b e3 [2] 8c e8 [2] 97 a6 [2] aa }

  condition:
    any of them
}