rule TTP_XOR_MULT_DOSStub_f343 {
  strings:
    $key_f343 = { a7 2b [2] d3 33 [2] 94 31 [2] d3 20 [2] 9d 2c [2] 91 26 [2] 86 2d [2] 9d 63 [2] a0 }

  condition:
    any of them
}