rule TTP_XOR_MULT_DOSStub_f332 {
  strings:
    $key_f332 = { a7 5a [2] d3 42 [2] 94 40 [2] d3 51 [2] 9d 5d [2] 91 57 [2] 86 5c [2] 9d 12 [2] a0 }

  condition:
    any of them
}