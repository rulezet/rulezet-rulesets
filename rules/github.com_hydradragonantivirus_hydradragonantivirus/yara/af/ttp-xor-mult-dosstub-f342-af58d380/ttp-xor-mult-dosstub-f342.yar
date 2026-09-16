rule TTP_XOR_MULT_DOSStub_f342 {
  strings:
    $key_f342 = { a7 2a [2] d3 32 [2] 94 30 [2] d3 21 [2] 9d 2d [2] 91 27 [2] 86 2c [2] 9d 62 [2] a0 }

  condition:
    any of them
}