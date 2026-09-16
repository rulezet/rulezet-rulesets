rule TTP_XOR_MULT_DOSStub_f354 {
  strings:
    $key_f354 = { a7 3c [2] d3 24 [2] 94 26 [2] d3 37 [2] 9d 3b [2] 91 31 [2] 86 3a [2] 9d 74 [2] a0 }

  condition:
    any of them
}