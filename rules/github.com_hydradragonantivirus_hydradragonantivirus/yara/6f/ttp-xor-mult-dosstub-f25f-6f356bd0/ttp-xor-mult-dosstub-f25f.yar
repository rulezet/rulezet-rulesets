rule TTP_XOR_MULT_DOSStub_f25f {
  strings:
    $key_f25f = { a6 37 [2] d2 2f [2] 95 2d [2] d2 3c [2] 9c 30 [2] 90 3a [2] 87 31 [2] 9c 7f [2] a1 }

  condition:
    any of them
}