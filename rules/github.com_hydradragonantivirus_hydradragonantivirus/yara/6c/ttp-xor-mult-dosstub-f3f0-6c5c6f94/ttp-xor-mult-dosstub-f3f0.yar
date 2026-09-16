rule TTP_XOR_MULT_DOSStub_f3f0 {
  strings:
    $key_f3f0 = { a7 98 [2] d3 80 [2] 94 82 [2] d3 93 [2] 9d 9f [2] 91 95 [2] 86 9e [2] 9d d0 [2] a0 }

  condition:
    any of them
}