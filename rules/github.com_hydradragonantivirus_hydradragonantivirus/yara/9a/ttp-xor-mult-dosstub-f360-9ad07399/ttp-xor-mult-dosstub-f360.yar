rule TTP_XOR_MULT_DOSStub_f360 {
  strings:
    $key_f360 = { a7 08 [2] d3 10 [2] 94 12 [2] d3 03 [2] 9d 0f [2] 91 05 [2] 86 0e [2] 9d 40 [2] a0 }

  condition:
    any of them
}