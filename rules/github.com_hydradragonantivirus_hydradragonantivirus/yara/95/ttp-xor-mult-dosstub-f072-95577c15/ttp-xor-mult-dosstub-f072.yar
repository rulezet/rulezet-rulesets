rule TTP_XOR_MULT_DOSStub_f072 {
  strings:
    $key_f072 = { a4 1a [2] d0 02 [2] 97 00 [2] d0 11 [2] 9e 1d [2] 92 17 [2] 85 1c [2] 9e 52 [2] a3 }

  condition:
    any of them
}