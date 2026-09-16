rule TTP_XOR_MULT_DOSStub_f43f {
  strings:
    $key_f43f = { a0 57 [2] d4 4f [2] 93 4d [2] d4 5c [2] 9a 50 [2] 96 5a [2] 81 51 [2] 9a 1f [2] a7 }

  condition:
    any of them
}