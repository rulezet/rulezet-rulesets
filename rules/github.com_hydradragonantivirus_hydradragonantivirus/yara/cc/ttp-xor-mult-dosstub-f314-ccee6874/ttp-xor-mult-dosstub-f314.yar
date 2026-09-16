rule TTP_XOR_MULT_DOSStub_f314 {
  strings:
    $key_f314 = { a7 7c [2] d3 64 [2] 94 66 [2] d3 77 [2] 9d 7b [2] 91 71 [2] 86 7a [2] 9d 34 [2] a0 }

  condition:
    any of them
}