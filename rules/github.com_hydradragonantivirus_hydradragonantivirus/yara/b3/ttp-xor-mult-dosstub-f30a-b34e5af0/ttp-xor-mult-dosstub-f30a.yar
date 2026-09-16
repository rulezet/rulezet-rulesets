rule TTP_XOR_MULT_DOSStub_f30a {
  strings:
    $key_f30a = { a7 62 [2] d3 7a [2] 94 78 [2] d3 69 [2] 9d 65 [2] 91 6f [2] 86 64 [2] 9d 2a [2] a0 }

  condition:
    any of them
}