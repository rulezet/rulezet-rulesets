rule TTP_XOR_MULT_DOSStub_f99b {
  strings:
    $key_f99b = { ad f3 [2] d9 eb [2] 9e e9 [2] d9 f8 [2] 97 f4 [2] 9b fe [2] 8c f5 [2] 97 bb [2] aa }

  condition:
    any of them
}