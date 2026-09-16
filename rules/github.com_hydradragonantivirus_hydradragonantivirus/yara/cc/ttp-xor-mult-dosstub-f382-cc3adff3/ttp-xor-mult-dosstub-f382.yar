rule TTP_XOR_MULT_DOSStub_f382 {
  strings:
    $key_f382 = { a7 ea [2] d3 f2 [2] 94 f0 [2] d3 e1 [2] 9d ed [2] 91 e7 [2] 86 ec [2] 9d a2 [2] a0 }

  condition:
    any of them
}