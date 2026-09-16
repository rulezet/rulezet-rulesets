rule TTP_XOR_MULT_DOSStub_f732 {
  strings:
    $key_f732 = { a3 5a [2] d7 42 [2] 90 40 [2] d7 51 [2] 99 5d [2] 95 57 [2] 82 5c [2] 99 12 [2] a4 }

  condition:
    any of them
}