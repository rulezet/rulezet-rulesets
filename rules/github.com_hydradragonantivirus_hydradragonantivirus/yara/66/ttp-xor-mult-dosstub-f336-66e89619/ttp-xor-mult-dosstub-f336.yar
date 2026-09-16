rule TTP_XOR_MULT_DOSStub_f336 {
  strings:
    $key_f336 = { a7 5e [2] d3 46 [2] 94 44 [2] d3 55 [2] 9d 59 [2] 91 53 [2] 86 58 [2] 9d 16 [2] a0 }

  condition:
    any of them
}