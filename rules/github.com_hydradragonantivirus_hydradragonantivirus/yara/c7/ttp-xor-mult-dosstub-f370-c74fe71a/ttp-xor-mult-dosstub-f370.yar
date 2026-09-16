rule TTP_XOR_MULT_DOSStub_f370 {
  strings:
    $key_f370 = { a7 18 [2] d3 00 [2] 94 02 [2] d3 13 [2] 9d 1f [2] 91 15 [2] 86 1e [2] 9d 50 [2] a0 }

  condition:
    any of them
}