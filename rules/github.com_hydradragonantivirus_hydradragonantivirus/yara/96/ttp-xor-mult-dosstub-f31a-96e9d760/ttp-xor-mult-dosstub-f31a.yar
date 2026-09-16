rule TTP_XOR_MULT_DOSStub_f31a {
  strings:
    $key_f31a = { a7 72 [2] d3 6a [2] 94 68 [2] d3 79 [2] 9d 75 [2] 91 7f [2] 86 74 [2] 9d 3a [2] a0 }

  condition:
    any of them
}