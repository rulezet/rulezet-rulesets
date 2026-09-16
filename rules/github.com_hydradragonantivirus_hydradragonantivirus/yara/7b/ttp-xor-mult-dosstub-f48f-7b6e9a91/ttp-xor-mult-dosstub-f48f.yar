rule TTP_XOR_MULT_DOSStub_f48f {
  strings:
    $key_f48f = { a0 e7 [2] d4 ff [2] 93 fd [2] d4 ec [2] 9a e0 [2] 96 ea [2] 81 e1 [2] 9a af [2] a7 }

  condition:
    any of them
}