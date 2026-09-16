rule TTP_XOR_MULT_DOSStub_f3e1 {
  strings:
    $key_f3e1 = { a7 89 [2] d3 91 [2] 94 93 [2] d3 82 [2] 9d 8e [2] 91 84 [2] 86 8f [2] 9d c1 [2] a0 }

  condition:
    any of them
}