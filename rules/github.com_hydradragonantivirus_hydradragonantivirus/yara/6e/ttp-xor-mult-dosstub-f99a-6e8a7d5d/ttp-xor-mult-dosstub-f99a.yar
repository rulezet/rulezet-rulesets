rule TTP_XOR_MULT_DOSStub_f99a {
  strings:
    $key_f99a = { ad f2 [2] d9 ea [2] 9e e8 [2] d9 f9 [2] 97 f5 [2] 9b ff [2] 8c f4 [2] 97 ba [2] aa }

  condition:
    any of them
}