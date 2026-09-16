rule TTP_XOR_MULT_DOSStub_f349 {
  strings:
    $key_f349 = { a7 21 [2] d3 39 [2] 94 3b [2] d3 2a [2] 9d 26 [2] 91 2c [2] 86 27 [2] 9d 69 [2] a0 }

  condition:
    any of them
}