rule TTP_XOR_MULT_DOSStub_7c83 {
  strings:
    $key_7c83 = { 28 eb [2] 5c f3 [2] 1b f1 [2] 5c e0 [2] 12 ec [2] 1e e6 [2] 09 ed [2] 12 a3 [2] 2f }

  condition:
    any of them
}