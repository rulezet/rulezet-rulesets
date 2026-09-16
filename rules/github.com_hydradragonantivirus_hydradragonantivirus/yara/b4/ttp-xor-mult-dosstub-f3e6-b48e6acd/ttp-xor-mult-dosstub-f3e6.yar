rule TTP_XOR_MULT_DOSStub_f3e6 {
  strings:
    $key_f3e6 = { a7 8e [2] d3 96 [2] 94 94 [2] d3 85 [2] 9d 89 [2] 91 83 [2] 86 88 [2] 9d c6 [2] a0 }

  condition:
    any of them
}