rule TTP_XOR_MULT_DOSStub_f344 {
  strings:
    $key_f344 = { a7 2c [2] d3 34 [2] 94 36 [2] d3 27 [2] 9d 2b [2] 91 21 [2] 86 2a [2] 9d 64 [2] a0 }

  condition:
    any of them
}