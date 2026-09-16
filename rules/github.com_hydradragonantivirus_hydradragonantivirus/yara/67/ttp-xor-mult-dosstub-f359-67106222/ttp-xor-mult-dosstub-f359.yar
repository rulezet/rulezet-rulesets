rule TTP_XOR_MULT_DOSStub_f359 {
  strings:
    $key_f359 = { a7 31 [2] d3 29 [2] 94 2b [2] d3 3a [2] 9d 36 [2] 91 3c [2] 86 37 [2] 9d 79 [2] a0 }

  condition:
    any of them
}