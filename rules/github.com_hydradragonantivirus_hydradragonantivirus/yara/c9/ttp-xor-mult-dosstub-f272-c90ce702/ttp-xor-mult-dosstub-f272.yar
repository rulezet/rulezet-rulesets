rule TTP_XOR_MULT_DOSStub_f272 {
  strings:
    $key_f272 = { a6 1a [2] d2 02 [2] 95 00 [2] d2 11 [2] 9c 1d [2] 90 17 [2] 87 1c [2] 9c 52 [2] a1 }

  condition:
    any of them
}