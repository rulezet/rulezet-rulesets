rule TTP_XOR_MULT_DOSStub_f305 {
  strings:
    $key_f305 = { a7 6d [2] d3 75 [2] 94 77 [2] d3 66 [2] 9d 6a [2] 91 60 [2] 86 6b [2] 9d 25 [2] a0 }

  condition:
    any of them
}