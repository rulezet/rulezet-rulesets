rule TTP_XOR_MULT_DOSStub_f983 {
  strings:
    $key_f983 = { ad eb [2] d9 f3 [2] 9e f1 [2] d9 e0 [2] 97 ec [2] 9b e6 [2] 8c ed [2] 97 a3 [2] aa }

  condition:
    any of them
}