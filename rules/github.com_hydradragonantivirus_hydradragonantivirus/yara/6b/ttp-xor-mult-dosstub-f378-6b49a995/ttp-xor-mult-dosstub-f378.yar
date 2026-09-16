rule TTP_XOR_MULT_DOSStub_f378 {
  strings:
    $key_f378 = { a7 10 [2] d3 08 [2] 94 0a [2] d3 1b [2] 9d 17 [2] 91 1d [2] 86 16 [2] 9d 58 [2] a0 }

  condition:
    any of them
}