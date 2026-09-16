rule TTP_XOR_MULT_DOSStub_f37d {
  strings:
    $key_f37d = { a7 15 [2] d3 0d [2] 94 0f [2] d3 1e [2] 9d 12 [2] 91 18 [2] 86 13 [2] 9d 5d [2] a0 }

  condition:
    any of them
}