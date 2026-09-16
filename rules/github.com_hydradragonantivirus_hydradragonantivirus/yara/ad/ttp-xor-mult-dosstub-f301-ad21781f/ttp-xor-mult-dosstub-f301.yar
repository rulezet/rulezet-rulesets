rule TTP_XOR_MULT_DOSStub_f301 {
  strings:
    $key_f301 = { a7 69 [2] d3 71 [2] 94 73 [2] d3 62 [2] 9d 6e [2] 91 64 [2] 86 6f [2] 9d 21 [2] a0 }

  condition:
    any of them
}