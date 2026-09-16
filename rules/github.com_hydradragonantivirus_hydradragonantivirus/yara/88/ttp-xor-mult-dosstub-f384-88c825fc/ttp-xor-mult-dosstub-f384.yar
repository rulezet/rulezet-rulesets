rule TTP_XOR_MULT_DOSStub_f384 {
  strings:
    $key_f384 = { a7 ec [2] d3 f4 [2] 94 f6 [2] d3 e7 [2] 9d eb [2] 91 e1 [2] 86 ea [2] 9d a4 [2] a0 }

  condition:
    any of them
}