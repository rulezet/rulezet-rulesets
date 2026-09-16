rule TTP_XOR_MULT_DOSStub_f35f {
  strings:
    $key_f35f = { a7 37 [2] d3 2f [2] 94 2d [2] d3 3c [2] 9d 30 [2] 91 3a [2] 86 31 [2] 9d 7f [2] a0 }

  condition:
    any of them
}