rule TTP_XOR_MULT_DOSStub_f340 {
  strings:
    $key_f340 = { a7 28 [2] d3 30 [2] 94 32 [2] d3 23 [2] 9d 2f [2] 91 25 [2] 86 2e [2] 9d 60 [2] a0 }

  condition:
    any of them
}