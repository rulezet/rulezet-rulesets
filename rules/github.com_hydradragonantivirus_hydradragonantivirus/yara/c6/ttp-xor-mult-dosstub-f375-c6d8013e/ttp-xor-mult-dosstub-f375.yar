rule TTP_XOR_MULT_DOSStub_f375 {
  strings:
    $key_f375 = { a7 1d [2] d3 05 [2] 94 07 [2] d3 16 [2] 9d 1a [2] 91 10 [2] 86 1b [2] 9d 55 [2] a0 }

  condition:
    any of them
}