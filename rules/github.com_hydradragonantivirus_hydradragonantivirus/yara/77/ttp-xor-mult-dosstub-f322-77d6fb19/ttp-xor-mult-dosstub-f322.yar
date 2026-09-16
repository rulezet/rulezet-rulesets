rule TTP_XOR_MULT_DOSStub_f322 {
  strings:
    $key_f322 = { a7 4a [2] d3 52 [2] 94 50 [2] d3 41 [2] 9d 4d [2] 91 47 [2] 86 4c [2] 9d 02 [2] a0 }

  condition:
    any of them
}