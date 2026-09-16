rule TTP_XOR_MULT_DOSStub_f33a {
  strings:
    $key_f33a = { a7 52 [2] d3 4a [2] 94 48 [2] d3 59 [2] 9d 55 [2] 91 5f [2] 86 54 [2] 9d 1a [2] a0 }

  condition:
    any of them
}