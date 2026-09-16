rule TTP_XOR_MULT_DOSStub_f18d {
  strings:
    $key_f18d = { a5 e5 [2] d1 fd [2] 96 ff [2] d1 ee [2] 9f e2 [2] 93 e8 [2] 84 e3 [2] 9f ad [2] a2 }

  condition:
    any of them
}