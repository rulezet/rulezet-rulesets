rule TTP_XOR_MULT_DOSStub_6c83 {
  strings:
    $key_6c83 = { 38 eb [2] 4c f3 [2] 0b f1 [2] 4c e0 [2] 02 ec [2] 0e e6 [2] 19 ed [2] 02 a3 [2] 3f }

  condition:
    any of them
}