rule TTP_XOR_MULT_DOSStub_f34a {
  strings:
    $key_f34a = { a7 22 [2] d3 3a [2] 94 38 [2] d3 29 [2] 9d 25 [2] 91 2f [2] 86 24 [2] 9d 6a [2] a0 }

  condition:
    any of them
}