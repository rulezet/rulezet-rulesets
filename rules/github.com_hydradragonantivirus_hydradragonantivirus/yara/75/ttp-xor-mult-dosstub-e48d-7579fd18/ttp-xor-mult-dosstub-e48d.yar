rule TTP_XOR_MULT_DOSStub_e48d {
  strings:
    $key_e48d = { b0 e5 [2] c4 fd [2] 83 ff [2] c4 ee [2] 8a e2 [2] 86 e8 [2] 91 e3 [2] 8a ad [2] b7 }

  condition:
    any of them
}