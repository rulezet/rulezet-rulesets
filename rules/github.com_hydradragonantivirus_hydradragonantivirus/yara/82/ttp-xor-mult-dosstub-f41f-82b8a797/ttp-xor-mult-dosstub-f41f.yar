rule TTP_XOR_MULT_DOSStub_f41f {
  strings:
    $key_f41f = { a0 77 [2] d4 6f [2] 93 6d [2] d4 7c [2] 9a 70 [2] 96 7a [2] 81 71 [2] 9a 3f [2] a7 }

  condition:
    any of them
}