rule TTP_XOR_MULT_DOSStub_f38d {
  strings:
    $key_f38d = { a7 e5 [2] d3 fd [2] 94 ff [2] d3 ee [2] 9d e2 [2] 91 e8 [2] 86 e3 [2] 9d ad [2] a0 }

  condition:
    any of them
}