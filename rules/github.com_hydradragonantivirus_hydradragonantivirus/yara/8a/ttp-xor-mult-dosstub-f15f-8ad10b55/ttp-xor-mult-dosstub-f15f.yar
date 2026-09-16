rule TTP_XOR_MULT_DOSStub_f15f {
  strings:
    $key_f15f = { a5 37 [2] d1 2f [2] 96 2d [2] d1 3c [2] 9f 30 [2] 93 3a [2] 84 31 [2] 9f 7f [2] a2 }

  condition:
    any of them
}