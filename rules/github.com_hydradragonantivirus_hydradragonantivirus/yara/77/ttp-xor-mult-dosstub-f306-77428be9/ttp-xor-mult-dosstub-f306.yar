rule TTP_XOR_MULT_DOSStub_f306 {
  strings:
    $key_f306 = { a7 6e [2] d3 76 [2] 94 74 [2] d3 65 [2] 9d 69 [2] 91 63 [2] 86 68 [2] 9d 26 [2] a0 }

  condition:
    any of them
}