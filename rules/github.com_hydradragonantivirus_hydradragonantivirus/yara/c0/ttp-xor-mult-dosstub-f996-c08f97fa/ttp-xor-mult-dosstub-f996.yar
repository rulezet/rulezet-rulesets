rule TTP_XOR_MULT_DOSStub_f996 {
  strings:
    $key_f996 = { ad fe [2] d9 e6 [2] 9e e4 [2] d9 f5 [2] 97 f9 [2] 9b f3 [2] 8c f8 [2] 97 b6 [2] aa }

  condition:
    any of them
}