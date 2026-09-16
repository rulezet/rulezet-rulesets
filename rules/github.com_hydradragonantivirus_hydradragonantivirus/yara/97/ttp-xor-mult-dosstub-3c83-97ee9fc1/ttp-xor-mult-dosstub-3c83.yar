rule TTP_XOR_MULT_DOSStub_3c83 {
  strings:
    $key_3c83 = { 68 eb [2] 1c f3 [2] 5b f1 [2] 1c e0 [2] 52 ec [2] 5e e6 [2] 49 ed [2] 52 a3 [2] 6f }

  condition:
    any of them
}