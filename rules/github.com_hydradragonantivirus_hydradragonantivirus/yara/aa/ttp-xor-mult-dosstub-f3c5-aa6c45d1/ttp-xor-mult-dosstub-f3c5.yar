rule TTP_XOR_MULT_DOSStub_f3c5 {
  strings:
    $key_f3c5 = { a7 ad [2] d3 b5 [2] 94 b7 [2] d3 a6 [2] 9d aa [2] 91 a0 [2] 86 ab [2] 9d e5 [2] a0 }

  condition:
    any of them
}