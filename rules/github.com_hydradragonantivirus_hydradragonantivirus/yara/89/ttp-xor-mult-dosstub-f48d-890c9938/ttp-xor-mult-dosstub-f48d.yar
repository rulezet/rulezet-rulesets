rule TTP_XOR_MULT_DOSStub_f48d {
  strings:
    $key_f48d = { a0 e5 [2] d4 fd [2] 93 ff [2] d4 ee [2] 9a e2 [2] 96 e8 [2] 81 e3 [2] 9a ad [2] a7 }

  condition:
    any of them
}